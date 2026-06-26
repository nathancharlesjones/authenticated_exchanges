import hmac
import hashlib
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as crypto_padding


def _sub_keys(key: bytes) -> tuple[bytes, bytes]:
    """Derive separate AES and HMAC sub-keys from the session key."""
    enc_key = hmac.new(key, b"enc", hashlib.sha256).digest()[:16]
    mac_key = hmac.new(key, b"mac", hashlib.sha256).digest()
    return enc_key, mac_key


def encrypt(key: bytes, plaintext: str) -> bytes:
    """Encrypt-then-MAC: AES-128-CBC with PKCS7 padding, then HMAC-SHA256."""
    enc_key, mac_key = _sub_keys(key)

    iv = os.urandom(16)
    padder = crypto_padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()
    encryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    mac = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    return iv + ciphertext + mac


def decrypt(key: bytes, data: bytes) -> str:
    """Verify MAC then decrypt. Raises ValueError on integrity failure."""
    enc_key, mac_key = _sub_keys(key)

    iv, ciphertext, mac_received = data[:16], data[16:-32], data[-32:]

    mac_expected = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(mac_received, mac_expected):
        raise ValueError("MAC verification failed — message tampered or wrong key")

    decryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = crypto_padding.PKCS7(128).unpadder()
    return (unpadder.update(padded) + unpadder.finalize()).decode()
