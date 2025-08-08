import os
import base64
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization

# --- Key Generation ---
def generate_keypair():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

# --- Serialization ---
def serialize_public_key(pub):
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return base64.b64encode(raw).decode()

def load_public_key(pub_b64):
    raw = base64.b64decode(pub_b64)
    return x25519.X25519PublicKey.from_public_bytes(raw)

def load_private_key(raw_bytes):
    return x25519.X25519PrivateKey.from_private_bytes(raw_bytes)

# --- Key Exchange ---
def derive_shared_key(private_key, peer_public_key):
    shared_secret = private_key.exchange(peer_public_key)
    # AESGCM requires 32 bytes (256-bit key) – X25519 gives 32 bytes already
    return shared_secret

# --- Encryption ---
def encrypt_message(shared_key, plaintext):
    aesgcm = AESGCM(shared_key)
    nonce = os.urandom(12)  # 96-bit nonce
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return nonce, ciphertext

# --- Decryption ---
def decrypt_message(shared_key, nonce, ciphertext):
    aesgcm = AESGCM(shared_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode()
