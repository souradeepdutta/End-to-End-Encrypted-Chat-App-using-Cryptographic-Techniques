import sys
import argparse
import threading
import queue
import os
from flask import Flask, render_template, request, redirect, url_for, jsonify # Ensure jsonify is imported

from socket_handler import SocketHandler
import crypto_utils # Used for initial key check/generation

# --- Global Variables ---
send_queue = queue.Queue()
receive_queue = queue.Queue()
message_history = [] # Simple in-memory history (shared state)
# Add a lock if complex state management needed, but likely okay for this simple poll
# history_lock = threading.Lock()
app = Flask(__name__)
socket_handler = None # Will be initialized later
config = {} # Will hold app configuration

# Ensure templates and static folders are found relative to script location
app.template_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
app.static_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')

def check_and_generate_keys(user_name):
    """Checks if signing keys exist, generates them if not."""
    private_key_path = f"{user_name.lower()}_private_signing_key.pem"
    public_key_path = f"{user_name.lower()}_public_signing_key.pem"

    if not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
        print(f"Signing keys for {user_name} not found. Generating new keys.")
        print(f"You will need to provide '{public_key_path}' to your peer.")
        print(f"And place your peer's public key as '{config['peer_name'].lower()}_public_signing_key.pem'.")
        # Ensure the password used here matches the one in crypto_utils.py
        _, _ = crypto_utils.generate_ecdsa_keys(private_key_path, public_key_path)
        # Add a small delay or prompt user to confirm key exchange before continuing
        input(">>> Keys generated. Please ensure peer public keys are exchanged, then press Enter to continue...")
    else:
        print(f"Using existing signing keys for {user_name}.")

# --- Flask Routes ---

@app.route('/', methods=['GET', 'POST'])
def index():
    """Handles initial page load and sending messages."""
    global message_history

    # Process any messages received *since the last check* on initial load or POST
    # This ensures the history is relatively up-to-date when the page first loads
    while not receive_queue.empty():
        try:
            msg = receive_queue.get_nowait()
            # with history_lock: # Use lock if implementing complex state
            message_history.append(msg)
            # System messages (like connect/disconnect) are handled by status endpoint now
            # but can remain in history if desired.
        except queue.Empty:
            break # No more messages

    if request.method == 'POST':
        message_text = request.form.get('message')
        if message_text:
            # Add "You: " prefix for storage in history, consistent with how JS expects it
            my_msg_display = f"You: {message_text}"
            # with history_lock:
            message_history.append(my_msg_display)
            # Put the raw message (without "You:") in the queue for the socket handler
            send_queue.put(message_text)
            # With AJAX form submission, this redirect is technically optional,
            # but good practice for non-JS fallback or direct POSTs.
            # The fetch call in JS handles the response itself.
            return redirect(url_for('index'))

    # Render the main page with the current full history
    # Pass a copy of history if using locks or concerned about modification during render
    # current_history = list(message_history)
    return render_template('index.html',
                           history=message_history, # Pass the current state
                           my_name=config.get('my_name', 'Me'),
                           peer_name=config.get('peer_name', 'Peer'))


@app.route('/get_messages')
def get_messages():
    """AJAX endpoint to fetch messages newer than a given index and connection status."""
    global message_history, socket_handler # Ensure socket_handler is accessible

    try:
        since_index = int(request.args.get('since', 0))
    except ValueError:
        since_index = 0

    # Process any newly arrived messages first to update history
    while not receive_queue.empty():
        try:
            msg = receive_queue.get_nowait()
            message_history.append(msg)
        except queue.Empty:
            break

    current_len = len(message_history)
    if since_index < 0:
        since_index = 0
    if since_index < current_len:
        new_messages = message_history[since_index:]
    else:
        new_messages = []

    # --- Get Connection Status ---
    # Check if socket_handler is initialized and get the event state
    # Assumes socket_handler.connection_active is a threading.Event()
    is_connected_status = socket_handler.connection_active.is_set() if socket_handler else False
    # ---------------------------

    # Return new messages, total count, and connection status
    return jsonify({
        'messages': new_messages,
        'total_count': current_len,
        'is_connected': is_connected_status # Include the connection status
    })


# --- Main Execution Logic ---
def main():
    global socket_handler, config

    parser = argparse.ArgumentParser(description="Simple E2EE Chat Application")
    parser.add_argument("name", help="Your username (e.g., Alice)")
    parser.add_argument("peer_name", help="Peer's username (e.g., Bob)")
    parser.add_argument("--listen-port", "-lp", type=int, required=True, help="Port number for this instance to listen on (if server) or use locally")
    parser.add_argument("--peer-host", "-ph", required=True, help="IP address of the peer to connect to")
    parser.add_argument("--peer-port", "-pp", type=int, required=True, help="Port number the peer is listening on")
    parser.add_argument("--server", "-s", action='store_true', help="Run this instance as the server (listener)")
    parser.add_argument("--flask-port", "-fp", type=int, default=5000, help="Port number for the Flask web UI")

    args = parser.parse_args()

    config = {
        'my_name': args.name,
        'peer_name': args.peer_name,
        'my_host': '0.0.0.0', # Listen on all interfaces if server
        'my_port': args.listen_port,
        'peer_host': args.peer_host,
        'peer_port': args.peer_port,
        'is_server': args.server,
        'flask_port': args.flask_port
    }

    print("--- Configuration ---")
    for key, val in config.items():
        print(f"{key}: {val}")
    print("---------------------")

    # --- Initial Key Setup ---
    check_and_generate_keys(args.name)
    peer_public_key_file = f"{args.peer_name.lower()}_public_signing_key.pem"
    if not os.path.exists(peer_public_key_file):
        print(f"\n!!! ERROR: Peer's public key file not found: {peer_public_key_file}")
        print(f"Please obtain {args.peer_name}'s public key and save it as {peer_public_key_file}")
        sys.exit(1)

    # --- Initialize and Start Socket Handler ---
    try:
        # Pass the global queues to the handler
        socket_handler = SocketHandler(config, send_queue, receive_queue)
        socket_handler.start() # Starts listener/connector and sender threads
    except Exception as e:
        print(f"\n!!! ERROR initializing socket handler: {e}")
        sys.exit(1)

    # --- Start Flask App ---
    print(f"\n>>> Flask UI running on http://127.0.0.1:{config['flask_port']}/ <<<")
    print(">>> Open this address in your web browser. <<<")
    print(">>> Terminal output will show cryptographic operations. <<<")
    # Run Flask in the main thread.
    # use_reloader=False is important when using background threads like this.
    app.run(host='0.0.0.0', port=config['flask_port'], debug=False, use_reloader=False)

    # --- Cleanup (Flask execution will block until stopped, e.g., Ctrl+C) ---
    print("Flask app stopped. Cleaning up...")
    if socket_handler:
        socket_handler.stop()
    print("Exiting.")

if __name__ == '__main__':
    main()