import hmac
import hashlib
import os

from derive_key import derive_key


class Reader:
    def __init__(self, master_key: bytes, reader_private_key):
        self.master_key = master_key
        self._private_key = reader_private_key

    def phase1_challenge(self) -> str:
        # Replace with `raise NotImplementedError` for actual exercise
        nonce_r = os.urandom(8).hex().upper()
        print(f"[READER] Sending challenge: {nonce_r}")
        return nonce_r

    def phase1_verify(self, uid: bytes, nonce_r: str, response_c: str) -> bool:
        # Replace with `raise NotImplementedError` for actual exercise
        card_key = derive_key(self.master_key, uid)
        expected = hmac.new(card_key, nonce_r.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(response_c, expected)

    def phase2_respond(self, nonce_c: str) -> bytes:
        # Replace with `raise NotImplementedError` for actual exercise
        sig = self._private_key.sign(nonce_c.encode())
        print(f"[READER] Signing reader challenge: {sig.hex()[:16]}...")
        return sig
