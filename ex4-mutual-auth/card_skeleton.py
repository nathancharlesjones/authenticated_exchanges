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
        print(f"[CARD]   Received challenge: {nonce_r}")
        response = hmac.new(self.card_key, nonce_r.encode(), hashlib.sha256).hexdigest()
        print(f"[CARD]   Sending response:   {response[:16]}...")
        return response

    def phase2_challenge(self) -> str:
        # TODO: generate a random 8-byte nonce (hex, uppercase),
        # store it as self._nonce_c, print it, and return it.
        raise NotImplementedError

    def phase2_verify(self, signature: bytes) -> bool:
        # TODO: verify that `signature` is a valid Ed25519 signature over
        # self._nonce_c.encode(), using self._reader_public_key.
        #
        # Call:  self._reader_public_key.verify(signature, self._nonce_c.encode())
        # That call raises InvalidSignature on failure; catch it and return False.
        # On success, print a verification message and return True.
        raise NotImplementedError
