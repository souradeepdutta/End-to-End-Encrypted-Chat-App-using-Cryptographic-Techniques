import socket
import threading
import struct
import time
from queue import Queue, Empty

import crypto_utils

# Constants for framing messages over socket
HEADER_LENGTH = 4 # Use 4 bytes to store the length of the message

class SocketHandler:
    def __init__(self, config, send_q: Queue, receive_q: Queue):
        self.config = config
        self.send_queue = send_q
        self.receive_queue = receive_q
        self.my_name = config['my_name']
        self.peer_name = config['peer_name']
        self.is_server = config['is_server']
        self.host = config['my_host']
        self.port = config['my_port']
        self.peer_host = config['peer_host']
        self.peer_port = config['peer_port']

        self.private_signing_key = None
        self.peer_public_signing_key = None
        self.session_aes_key = None
        self.client_socket = None
        self.stop_event = threading.Event()
        self.connection_active = threading.Event() # Signal when connection and key exchange are done

        self._load_keys()

    def _load_keys(self):
        """Load own private and peer's public signing keys."""
        my_private_key_path = f"{self.my_name.lower()}_private_signing_key.pem"
        my_public_key_path = f"{self.my_name.lower()}_public_signing_key.pem"
        peer_public_key_path = f"{self.peer_name.lower()}_public_signing_key.pem"

        self.private_signing_key = crypto_utils.load_private_signing_key(my_private_key_path)
        if not self.private_signing_key:
             # Try generating if loading failed
             print(f"Private key not found or failed to load, attempting to generate...")
             # Check if public key exists too, avoid overwriting just one
             if not os.path.exists(my_public_key_path):
                 self.private_signing_key, _ = crypto_utils.generate_ecdsa_keys(
                     my_private_key_path, my_public_key_path
                 )
             if not self.private_signing_key:
                 raise Exception("Failed to load or generate private signing key.")

        self.peer_public_signing_key = crypto_utils.load_public_signing_key(peer_public_key_path)
        if not self.peer_public_signing_key:
            raise Exception(f"Failed to load peer's public key from {peer_public_key_path}. Make sure the file exists and contains the correct public key.")

    def _send_framed(self, data):
        """Prefixes data with its length and sends it."""
        if not self.client_socket:
            print("[Socket Error] No active socket to send.")
            return False
        try:
            msg_len = len(data)
            header = struct.pack('>I', msg_len) # Pack length into 4 bytes, big-endian
            self.client_socket.sendall(header + data)
            # print(f"[Socket] Sent {msg_len} bytes.") # Verbose
            return True
        except socket.error as e:
            print(f"[Socket Error] Failed to send data: {e}")
            self._handle_disconnect()
            return False

    def _recv_framed(self):
        """Receives framed data (length prefixed)."""
        if not self.client_socket:
            return None
        try:
            # Receive the header (4 bytes)
            header = self.client_socket.recv(HEADER_LENGTH)
            if not header or len(header) < HEADER_LENGTH:
                print("[Socket] Connection closed by peer (or header incomplete).")
                self._handle_disconnect()
                return None

            msg_len = struct.unpack('>I', header)[0]
            # print(f"[Socket] Receiving message of length: {msg_len}") # Verbose

            # Receive the full message
            data = b''
            while len(data) < msg_len:
                chunk = self.client_socket.recv(min(msg_len - len(data), 4096))
                if not chunk:
                    print("[Socket Error] Connection broken while receiving data.")
                    self._handle_disconnect()
                    return None
                data += chunk
            # print(f"[Socket] Received {len(data)} bytes.") # Verbose
            return data
        except socket.error as e:
            print(f"[Socket Error] Failed to receive data: {e}")
            self._handle_disconnect()
            return None
        except struct.error as e:
             print(f"[Socket Error] Failed to unpack header: {e}")
             self._handle_disconnect()
             return None

    def _perform_key_exchange(self):
        """Handles the ECDH key exchange and signature verification."""
        print("[Socket] Starting key exchange...")
        try:
            # 1. Generate ephemeral keys
            private_key_eph, public_key_eph = crypto_utils.generate_ephemeral_ecdh_keys()
            public_key_eph_pem = crypto_utils.serialize_public_key(public_key_eph)

            # 2. Sign ephemeral public key
            signature = crypto_utils.sign_data(self.private_signing_key, public_key_eph_pem)

            # 3. Send own public key and signature
            print("[Socket] Sending ephemeral public key and signature...")
            if not self._send_framed(public_key_eph_pem): return False
            if not self._send_framed(signature): return False
            print("[Socket] Sent own key material.")

            # 4. Receive peer's public key and signature
            print("[Socket] Receiving peer's ephemeral public key and signature...")
            peer_public_key_eph_pem = self._recv_framed()
            if not peer_public_key_eph_pem: return False
            peer_signature = self._recv_framed()
            if not peer_signature: return False
            print("[Socket] Received peer's key material.")

            # 5. Verify peer's signature
            print("[Socket] Verifying peer's signature...")
            if not crypto_utils.verify_signature(self.peer_public_signing_key, peer_signature, peer_public_key_eph_pem):
                print("[Socket Error] !!! Peer signature verification failed! Aborting. !!!")
                return False
            print("[Socket] Peer signature verified.")

            # Deserialize peer's public key AFTER verification
            peer_public_key_eph = crypto_utils.deserialize_public_key(peer_public_key_eph_pem)
            if not peer_public_key_eph:
                 print("[Socket Error] Failed to deserialize peer's public key.")
                 return False

            # 6. Perform ECDH
            shared_secret = crypto_utils.perform_ecdh(private_key_eph, peer_public_key_eph)

            # 7. Derive AES session key
            self.session_aes_key = crypto_utils.derive_aes_key(shared_secret)

            print("[Socket] *** Secure session established! ***")
            self.connection_active.set() # Signal that connection and keys are ready
            return True

        except Exception as e:
            print(f"[Socket Error] Key exchange failed: {e}")
            return False

    def _handle_connection(self, conn):
        """Manages a single connection after it's established."""
        self.client_socket = conn
        if not self._perform_key_exchange():
            print("[Socket] Key exchange failed. Closing connection.")
            self._close_socket()
            return # Exit thread if key exchange fails

        # Start receiver loop in this thread after key exchange
        self._receiver_loop()

        # If receiver loop finishes (disconnect), cleanup
        self._handle_disconnect()

    def _receiver_loop(self):
        """Listens for incoming messages and puts them in the receive queue."""
        print("[Socket] Receiver loop started.")
        while not self.stop_event.is_set() and self.client_socket:
            try:
                # Receive framed data (Nonce || CiphertextWithTag)
                # Assume nonce is fixed length, sent first
                nonce_data = self.client_socket.recv(crypto_utils.NONCE_LENGTH)
                if not nonce_data or len(nonce_data) < crypto_utils.NONCE_LENGTH:
                     print("[Socket] Peer disconnected (nonce recv).")
                     break

                # Then receive the framed ciphertext
                ciphertext_with_tag = self._recv_framed()
                if ciphertext_with_tag is None:
                     # Error or disconnect handled in _recv_framed
                     break

                # Decrypt
                plaintext = crypto_utils.decrypt_message(self.session_aes_key, nonce_data, ciphertext_with_tag)

                if plaintext:
                    # print(f"[Socket] Received and decrypted: {plaintext}") # Can be verbose
                    self.receive_queue.put(f"{self.peer_name}: {plaintext}")
                else:
                    # Decryption failed - message might be corrupted or key mismatch
                    # Decide how to handle: ignore, notify user, terminate?
                    print("[Socket] Received message failed decryption/verification.")
                    # For simplicity, just ignore the bad message here.
                    # In a real app, might terminate or require re-keying.

            except socket.timeout:
                 continue # No data received, loop again
            except socket.error as e:
                print(f"[Socket Error] Receiver loop error: {e}")
                break # Exit loop on socket error
            except Exception as e:
                print(f"[Error] Unexpected error in receiver loop: {e}")
                break # Exit loop on other errors

        print("[Socket] Receiver loop finished.")


    def _sender_loop(self):
        """Checks send queue and sends messages."""
        print("[Socket] Sender loop started.")
        while not self.stop_event.is_set():
            try:
                # Wait briefly for a message or timeout
                message = self.send_queue.get(timeout=0.5)
                if message and self.session_aes_key and self.client_socket and self.connection_active.is_set():
                    print(f"[Socket] Encrypting and sending: {message}")
                    nonce, ciphertext_with_tag = crypto_utils.encrypt_message(self.session_aes_key, message)

                    # Send nonce (fixed length) then framed ciphertext
                    try:
                        self.client_socket.sendall(nonce)
                        if not self._send_framed(ciphertext_with_tag):
                            print("[Socket] Failed to send message in sender loop.")
                            # Error handled in _send_framed, might trigger disconnect
                    except socket.error as e:
                        print(f"[Socket Error] Sender loop error: {e}")
                        self._handle_disconnect()
                        # Optional: Put message back in queue? Depends on desired behavior
                        # self.send_queue.put(message) # Re-queue if send failed
                        break # Exit sender loop on error

                self.send_queue.task_done() # Mark task as completed

            except Empty:
                continue # No message in queue, loop again
            except Exception as e:
                print(f"[Error] Unexpected error in sender loop: {e}")
                break # Exit loop on other errors

        print("[Socket] Sender loop finished.")


    def start(self):
        """Starts the socket handling (server listen or client connect) in threads."""
        print("[Socket] Starting handler...")
        self.stop_event.clear()
        self.connection_active.clear()

        if self.is_server:
            self.listen_thread = threading.Thread(target=self._run_server, daemon=True)
            self.listen_thread.start()
        else:
            self.connect_thread = threading.Thread(target=self._run_client, daemon=True)
            self.connect_thread.start()

        # Start sender thread once (it waits for connection_active)
        self.sender_thread = threading.Thread(target=self._sender_loop, daemon=True)
        self.sender_thread.start()


    def _run_server(self):
        """Listens for incoming connections."""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server_socket.bind((self.host, self.port))
            server_socket.listen(1)
            print(f"[Socket Server] Listening on {self.host}:{self.port}...")

            while not self.stop_event.is_set():
                try:
                    # Set a timeout so the loop can check stop_event
                    server_socket.settimeout(1.0)
                    conn, addr = server_socket.accept()
                    server_socket.settimeout(None) # Back to blocking for the connection
                    print(f"[Socket Server] Connection accepted from {addr}")
                    # Handle this connection (runs receiver loop inside)
                    # Server only handles one connection in this simple example
                    self._handle_connection(conn)
                    # If _handle_connection returns, it means disconnect
                    print("[Socket Server] Peer disconnected. Ready for new connection (restart app).")
                    # In this simple model, we exit after one connection cycle
                    break
                except socket.timeout:
                    continue # Check stop_event again
                except Exception as e:
                    print(f"[Socket Server] Error accepting connection: {e}")
                    time.sleep(1) # Avoid busy-looping on error
        except Exception as e:
             print(f"[Socket Server] Failed to bind/listen: {e}")
        finally:
            print("[Socket Server] Closing server socket.")
            server_socket.close()
            self._handle_disconnect() # Ensure cleanup


    def _run_client(self):
        """Connects to the server."""
        print(f"[Socket Client] Attempting to connect to {self.peer_host}:{self.peer_port}...")
        while not self.stop_event.is_set():
            try:
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.settimeout(5.0) # Connection timeout
                client_socket.connect((self.peer_host, self.peer_port))
                client_socket.settimeout(None) # Back to blocking for operations
                print("[Socket Client] Connected successfully!")
                # Handle this connection (runs receiver loop inside)
                self._handle_connection(client_socket)
                # If _handle_connection returns, it means disconnect
                print("[Socket Client] Disconnected from server.")
                break # Exit after disconnect in this simple model
            except socket.timeout:
                 print("[Socket Client] Connection attempt timed out. Retrying in 5s...")
                 time.sleep(5)
            except socket.error as e:
                print(f"[Socket Client] Connection failed: {e}. Retrying in 5s...")
                time.sleep(5)
            except Exception as e:
                print(f"[Socket Client] Unexpected error during connection: {e}")
                break # Exit on unexpected errors
        self._handle_disconnect() # Ensure cleanup


    def _handle_disconnect(self):
        """Handles cleanup when a disconnection occurs."""
        if self.connection_active.is_set():
             print("[Socket] Connection lost.")
             self.receive_queue.put("--- Connection Lost ---")
        self.connection_active.clear()
        self.session_aes_key = None # Invalidate session key
        self._close_socket()


    def _close_socket(self):
        """Safely closes the client socket."""
        if self.client_socket:
            print("[Socket] Closing socket.")
            try:
                self.client_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass # Ignore if already closed
            finally:
                self.client_socket.close()
                self.client_socket = None

    def stop(self):
        """Stops the handler threads and closes sockets."""
        print("[Socket] Stopping handler...")
        self.stop_event.set()
        self._close_socket()
        # No need to explicitly join daemon threads usually,
        # but good practice if you need guaranteed cleanup before exit.
        # if hasattr(self, 'listen_thread') and self.listen_thread.is_alive(): self.listen_thread.join(timeout=1)
        # if hasattr(self, 'connect_thread') and self.connect_thread.is_alive(): self.connect_thread.join(timeout=1)
        # if hasattr(self, 'sender_thread') and self.sender_thread.is_alive(): self.sender_thread.join(timeout=1)
        print("[Socket] Handler stopped.")