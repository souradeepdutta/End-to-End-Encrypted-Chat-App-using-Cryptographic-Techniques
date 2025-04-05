import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.exceptions import InvalidSignature

# --- Constants ---
CURVE = ec.SECP384R1()
SIGNING_ALGORITHM = ec.ECDSA(hashes.SHA256())
HASH_ALGORITHM = hashes.SHA256()
AES_KEY_LENGTH = 32  # 256 bits
NONCE_LENGTH = 12    # Standard for AES-GCM
HKDF_INFO = b'e2ee chat session key'
KEY_PASSWORD = b'verysecurepassword' # !!! CHANGE THIS OR USE BETTER METHOD IN REAL APP !!!

# --- Key Management ---

def generate_ecdsa_keys(private_key_path, public_key_path):
    """Generates ECDSA signing keys and saves them to PEM files."""
    print("[Crypto] Generating new ECDSA signing key pair...")
    private_key = ec.generate_private_key(CURVE)
    public_key = private_key.public_key()

    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(KEY_PASSWORD)
    )
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    try:
        with open(private_key_path, 'wb') as f:
            f.write(pem_private)
        with open(public_key_path, 'wb') as f:
            f.write(pem_public)
        print(f"[Crypto] Keys saved to {private_key_path} and {public_key_path}")
        return private_key, public_key
    except IOError as e:
        print(f"[Crypto Error] Could not write key files: {e}")
        return None, None

def load_private_signing_key(path):
    """Loads a private ECDSA key from a PEM file."""
    try:
        with open(path, 'rb') as key_file:
            private_key = load_pem_private_key(
                key_file.read(),
                password=KEY_PASSWORD # Use None if key is not encrypted
            )
        print(f"[Crypto] Private signing key loaded from {path}")
        return private_key
    except (IOError, ValueError, TypeError) as e:
        print(f"[Crypto Error] Could not load private key from {path}: {e}")
        return None

def load_public_signing_key(path):
    """Loads a public ECDSA key from a PEM file."""
    try:
        with open(path, 'rb') as key_file:
            public_key = load_pem_public_key(key_file.read())
        print(f"[Crypto] Public signing key loaded from {path}")
        return public_key
    except (IOError, ValueError) as e:
        print(f"[Crypto Error] Could not load public key from {path}: {e}")
        return None

def generate_ephemeral_ecdh_keys():
    """Generates a new ephemeral ECDH key pair."""
    print("[Crypto] Generating ephemeral ECDH key pair...")
    private_key_eph = ec.generate_private_key(CURVE)
    public_key_eph = private_key_eph.public_key()
    return private_key_eph, public_key_eph

# --- Serialization ---

def serialize_public_key(public_key):
    """Serializes a public key to PEM bytes."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(pem_bytes):
    """Deserializes PEM bytes to a public key object."""
    try:
        return load_pem_public_key(pem_bytes)
    except ValueError as e:
        print(f"[Crypto Error] Could not deserialize public key: {e}")
        return None

# --- Signing and Verification ---

def sign_data(private_signing_key, data):
    """Signs data using the private signing key."""
    print("[Crypto] Signing data...")
    return private_signing_key.sign(data, SIGNING_ALGORITHM)

def verify_signature(public_signing_key, signature, data):
    """Verifies a signature using the public signing key."""
    try:
        public_signing_key.verify(signature, data, SIGNING_ALGORITHM)
        print("[Crypto] Signature verified successfully.")
        return True
    except InvalidSignature:
        print("[Crypto Error] !!! SIGNATURE VERIFICATION FAILED !!!")
        return False
    except Exception as e:
        print(f"[Crypto Error] Verification unexpected error: {e}")
        return False

# --- Key Exchange and Derivation ---

def perform_ecdh(private_key_eph, peer_public_key_eph):
    """Performs ECDH key exchange."""
    print("[Crypto] Performing ECDH key exchange...")
    shared_secret = private_key_eph.exchange(ec.ECDH(), peer_public_key_eph)
    print("[Crypto] Shared secret computed.")
    return shared_secret

def derive_aes_key(shared_secret):
    """Derives an AES key from the shared secret using HKDF."""
    print("[Crypto] Deriving AES session key using HKDF...")
    hkdf = HKDF(
        algorithm=HASH_ALGORITHM,
        length=AES_KEY_LENGTH,
        salt=None, # Salt can enhance security, could be derived from exchange
        info=HKDF_INFO,
    )
    aes_key = hkdf.derive(shared_secret)
    print("[Crypto] AES session key derived.")
    return aes_key

# --- Symmetric Encryption/Decryption ---

def encrypt_message(aes_key, plaintext):
    """Encrypts a message using AES-GCM."""
    if not isinstance(plaintext, bytes):
        plaintext = plaintext.encode('utf-8')
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(NONCE_LENGTH)
    print(f"[Crypto] Encrypting message with nonce: {nonce.hex()}")
    # encrypt() returns ciphertext which includes the authentication tag
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None) # None = No Additional Associated Data
    return nonce, ciphertext_with_tag

def decrypt_message(aes_key, nonce, ciphertext_with_tag):
    """Decrypts a message using AES-GCM and verifies its integrity."""
    aesgcm = AESGCM(aes_key)
    print(f"[Crypto] Decrypting message with nonce: {nonce.hex()}")
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
        print("[Crypto] Message decrypted and verified successfully.")
        return plaintext.decode('utf-8')
    except InvalidSignature: # cryptography raises InvalidSignature for tag mismatch
        print("[Crypto Error] !!! MESSAGE DECRYPTION FAILED (Invalid Tag / Tampered) !!!")
        return None
    except Exception as e:
        print(f"[Crypto Error] Decryption unexpected error: {e}")
        return None