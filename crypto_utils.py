# crypto_utils.py
import base64
import os
import hashlib
import time
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---- Password hashing (for auth only) ----
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

# ---- X25519 key helpers ----
def generate_x25519_keypair():
    private = X25519PrivateKey.generate()
    public = private.public_key()
    return private, public

def serialize_public_key(pub: X25519PublicKey) -> str:
    raw = pub.public_bytes()  # raw bytes
    return base64.b64encode(raw).decode()

def deserialize_public_key(b64: str) -> X25519PublicKey:
    raw = base64.b64decode(b64)
    return X25519PublicKey.from_public_bytes(raw)

def serialize_private_key_bytes(priv: X25519PrivateKey) -> str:
    # WARNING: only for local client storage (never send to server).
    raw = priv.private_bytes()
    return base64.b64encode(raw).decode()

def deserialize_private_key_bytes(b64: str) -> X25519PrivateKey:
    raw = base64.b64decode(b64)
    return X25519PrivateKey.from_private_bytes(raw)

# ---- Derive symmetric key from ECDH shared secret ----
def derive_aes_key(shared_secret: bytes, info: bytes = b"secure-chat-e2ee") -> bytes:
    hkdf = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=info,
    )
    return hkdf.derive(shared_secret)

# ---- AES-GCM encrypt/decrypt ----
def encrypt_with_key(aes_key: bytes, plaintext: str) -> (bytes, bytes):
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return nonce, ct  # both bytes

def decrypt_with_key(aes_key: bytes, nonce: bytes, ciphertext: bytes) -> str:
    aesgcm = AESGCM(aes_key)
    pt = aesgcm.decrypt(nonce, ciphertext, None)
    return pt.decode()

# convenience base64 helpers
def b64(x: bytes) -> str:
    return base64.b64encode(x).decode()

def ub64(s: str) -> bytes:
    return base64.b64decode(s)
