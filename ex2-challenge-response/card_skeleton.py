import hmac
import hashlib


def compute_response(key: bytes, nonce: str) -> str:
    # TODO: return HMAC-SHA256(key, nonce), hex-encoded
    raise NotImplementedError


class Card:
    def __init__(self, uid: bytes, key: bytes):
        self.uid = uid.upper()
        self.key = key

    def respond(self, nonce: str) -> str:
        print(f"[CARD]   Received challenge: {nonce}")
        response = compute_response(self.key, nonce)
        print(f"[CARD]   Sending response:   {response[:16]}...")
        return response
