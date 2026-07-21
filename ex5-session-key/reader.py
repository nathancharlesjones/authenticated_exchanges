import hmac
import hashlib
import os

from derive_key import derive_key


class Reader:
    def __init__(self, fleet_key: bytes, signing_private_key):
        self.fleet_key = fleet_key
        self._signing_key = signing_private_key

    def phase1_challenge(self) -> str:
        nonce1 = os.urandom(8).hex().upper()
        print(f"[READER] Sending challenge: {nonce1}")
        return nonce1

    def phase1_verify(self, uid: bytes, nonce1: str, mac: str) -> bool:
        device_key = derive_key(self.fleet_key, uid, b"badge_auth")
        expected = hmac.new(device_key, nonce1.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(mac, expected)

    def phase2_sign(self, nonce2: str) -> bytes:
        sig = self._signing_key.sign(nonce2.encode())
        print(f"[READER] Signing reader challenge: {sig.hex()[:16]}...")
        return sig

    def derive_info_key(self, uid: bytes) -> bytes:
        """Look up the badge's pre-shared info key, same as the one baked in at provisioning."""
        info_key = derive_key(self.fleet_key, uid, b"info_encryption")
        print(f"[READER] Info key derived (uid={uid.decode()}).")
        return info_key
