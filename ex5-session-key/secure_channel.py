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
    def __init__(self, session_key: bytes, reader, card):
        self.session_key = session_key
        self._reader = reader
        self._card = card

    def send_command(self, command: str) -> str:
        enc_command = encrypt(self.session_key, command)
        print(f"[READER] Sending encrypted command: {enc_command.hex()[:16]}...")

        decrypted_command = decrypt(self.session_key, enc_command)
        print(f"[CARD]   Decrypted command: {decrypted_command}")
        response = self._card.handle_command(decrypted_command)

        enc_response = encrypt(self.session_key, response)
        print(f"[CARD]   Sending encrypted response: {enc_response.hex()[:16]}...")

        final = decrypt(self.session_key, enc_response)
        print(f"[READER] Decrypted response: {final}")
        return final
