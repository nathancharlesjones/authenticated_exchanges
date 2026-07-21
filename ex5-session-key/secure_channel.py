import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt(key: bytes, plaintext: str) -> bytes:
    """Encrypt with AES-128-GCM. Returns IV + ciphertext+tag."""
    iv = os.urandom(12)
    return iv + AESGCM(key).encrypt(iv, plaintext.encode(), None)


def decrypt(key: bytes, data: bytes) -> str:
    """Decrypt AES-128-GCM. Raises InvalidTag if key is wrong or data is tampered."""
    return AESGCM(key).decrypt(data[:12], data[12:], None).decode()


class SecureChannel:
    def __init__(self, info_key: bytes, reader, badge):
        self.info_key = info_key
        self._reader = reader
        self._badge = badge

    def send_command(self, command: str) -> str:
        enc_command = encrypt(self.info_key, command)
        print(f"[READER] Sending encrypted command: {enc_command.hex()[:16]}...")

        decrypted_command = decrypt(self.info_key, enc_command)
        print(f"[BADGE]   Decrypted command: {decrypted_command}")
        response = self._badge.handle_command(decrypted_command)

        enc_response = encrypt(self.info_key, response)
        print(f"[BADGE]   Sending encrypted response: {enc_response.hex()[:16]}...")

        final = decrypt(self.info_key, enc_response)
        print(f"[READER] Decrypted response: {final}")
        return final
