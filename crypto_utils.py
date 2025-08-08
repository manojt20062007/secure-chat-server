# crypto_utils.py
import os
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Default static key (for quick testing). **Replace** in production with per-user keys or proper KEX.
# Provide base64 encoded 16/24/32-byte key in env var AES_KEY_B64 (recommended).
DEFAULT_B64 = os.environ.get("AES_KEY_B64", "9v2GjaRMNxD8ez1BlIfnCg==")
SECRET_KEY = base64.urlsafe_b64decode(DEFAULT_B64)
aesgcm = AESGCM(SECRET_KEY)

def encrypt_message(msg: str) -> str:
    """
    Encrypts a text message and returns base64(nonce + ciphertext)
    """
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, msg.encode("utf-8"), None)
    return base64.b64encode(nonce + ct).decode("utf-8")

def decrypt_message(b64data: str) -> str:
    """
    Decrypts base64(nonce + ciphertext) -> plaintext string
    """
    blob = base64.b64decode(b64data)
    nonce = blob[:12]
    ciphertext = blob[12:]
    pt = aesgcm.decrypt(nonce, ciphertext, None)
    return pt.decode("utf-8")

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()
