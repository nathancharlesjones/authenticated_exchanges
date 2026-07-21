import hmac
import hashlib


def compute_response(key: bytes, nonce: str) -> str:
    return hmac.new(key, nonce.encode(), hashlib.sha256).hexdigest()


class Badge:
    def __init__(self, uid: bytes, key: bytes):
        self.uid = uid.upper()
        self.key = key

    def respond(self, nonce: str) -> str:
        print(f"[BADGE]   Received challenge: {nonce}")
        response = compute_response(self.key, nonce)
        print(f"[BADGE]   Sending response:   {response[:16]}...")
        return response
