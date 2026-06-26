import hmac
import hashlib
import os

from cryptography.exceptions import InvalidSignature


class Card:
    def __init__(self, uid: bytes, card_key: bytes, reader_public_key):
        self.uid = uid.upper()
        self.card_key = card_key
        self._reader_public_key = reader_public_key
        self._nonce_c = None

    def phase1_respond(self, nonce_r: str) -> str:
        # Replace with `raise NotImplementedError` for actual exercise
        print(f"[CARD]   Received challenge: {nonce_r}")
        response = hmac.new(self.card_key, nonce_r.encode(), hashlib.sha256).hexdigest()
        print(f"[CARD]   Sending response:   {response[:16]}...")
        return response

    def phase2_challenge(self) -> str:
        # Replace with `raise NotImplementedError` for actual exercise
        self._nonce_c = os.urandom(8).hex().upper()
        print(f"[CARD]   Issuing reader challenge: {self._nonce_c}")
        return self._nonce_c

    def phase2_verify(self, signature: bytes) -> bool:
        # Replace with `raise NotImplementedError` for actual exercise
        try:
            self._reader_public_key.verify(signature, self._nonce_c.encode())
            print("[CARD]   Reader signature verified. ✓")
            return True
        except InvalidSignature:
            print("[CARD]   Reader signature invalid. Rejecting.")
            return False
