# End-to-End Encrypted (E2EE) Chat Application

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Cryptography-ECDH%20%7C%20ECDSA%20%7C%20AES--GCM-green.svg)](#)

A peer-to-peer End-to-End Encrypted (E2EE) chat application demonstrating core cryptographic protocols for secure communication. Built with Python sockets and a modern Flask web interface, this application showcases forward secrecy, mutual peer authentication, and authenticated symmetric encryption.

> [!NOTE]
> **Educational Demonstration**: This project is intended for educational and research purposes to demonstrate real-world cryptographic handshakes and message security over raw TCP sockets.

---

## 🔒 Security Architecture & Cryptographic Flow

```mermaid
sequenceDiagram
    autonumber
    participant Alice as Client A (Initiator)
    participant Bob as Client B (Receiver)

    Note over Alice,Bob: 1. Identity & Key Setup (ECDSA P-384)
    Alice->>Bob: Connection Request (TCP Socket)
    
    Note over Alice,Bob: 2. Authenticated Handshake (ECDH + ECDSA)
    Alice->>Bob: Ephemeral ECDH Public Key + ECDSA Signature
    Bob->>Bob: Verify Alice's Signature using Long-Term Identity Key
    Bob->>Alice: Ephemeral ECDH Public Key + ECDSA Signature
    Alice->>Alice: Verify Bob's Signature using Long-Term Identity Key

    Note over Alice,Bob: 3. Key Derivation (HKDF-SHA256)
    Alice->>Alice: Derive AES-256 Symmetric Session Key via HKDF
    Bob->>Bob: Derive AES-256 Symmetric Session Key via HKDF

    Note over Alice,Bob: 4. Secure Message Exchange (AES-256-GCM)
    Alice->>Bob: Encrypted Payload (Ciphertext + 12-byte Nonce + 16-byte Auth Tag)
    Bob->>Bob: Authenticate & Decrypt Payload
    Bob->>Alice: Encrypted Response Payload
```

---

## ✨ Core Features

* **Authenticated Key Exchange**: Uses **ECDH** (SECP384R1 curve) for ephemeral session key negotiation, mutually authenticated via **ECDSA** (SECP384R1, SHA-256) signatures to prevent Man-in-the-Middle (MitM) attacks.
* **Forward Secrecy**: Generating ephemeral keypairs for every session ensures that past session traffic cannot be decrypted even if long-term signing keys are ever compromised.
* **Symmetric Message Confidentiality**: Fast, secure message encryption with **AES-256-GCM**, providing both confidentiality and cryptographic integrity verification via authentication tags.
* **Robust Key Derivation**: Applies **HKDF** (HMAC-based Extract-and-Expand Key Derivation Function with SHA-256) to derive uniform session keys.
* **Intuitive Web UI**: Modern, responsive interface built with Flask, HTML5, CSS3, and AJAX polling for seamless live messaging.
* **Detailed Terminal Diagnostics**: Verbose console logging illustrating handshake states, signature validation, nonces, and ciphertexts in real time.

---

## 📁 Repository Structure

```
├── app.py                 # Flask web server & AJAX message router
├── crypto_utils.py        # ECDH, ECDSA, HKDF, & AES-256-GCM cryptographic routines
├── socket_handler.py      # Direct TCP socket client/server and handshake state machine
├── requirements.txt       # Project dependencies
├── templates/
│   └── index.html         # Web chat interface
├── static/
│   └── style.css          # Modern chat UI styling
└── LICENSE                # MIT License
```

---

## 🚀 Quick Start

### 1. Installation
```bash
git clone https://github.com/souradeepdutta/End-to-End-Encrypted-Chat-App-using-Cryptographic-Techniques.git
cd End-to-End-Encrypted-Chat-App-using-Cryptographic-Techniques

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Running the Two Chat Peers
To simulate a chat between two users on the same machine:

```bash
# Terminal 1: Launch Peer 1 (Host / Server)
python app.py --port 5000 --socket-port 9000 --role server

# Terminal 2: Launch Peer 2 (Client)
python app.py --port 5001 --socket-port 9000 --peer-ip 127.0.0.1 --role client
```

* Open `http://localhost:5000` for User 1.
* Open `http://localhost:5001` for User 2.
* Connect, exchange authenticated keys, and start chatting securely!

---

## 📜 License
This project is licensed under the [MIT License](LICENSE).
