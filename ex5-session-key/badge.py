import hmac
import hashlib
import os

from cryptography.exceptions import InvalidSignature


class Badge:
    def __init__(self, uid: bytes, device_key: bytes, info_key: bytes, signing_public_key):
        self.uid = uid.upper()
        self.device_key = device_key
        self.info_key = info_key
        self._signing_public_key = signing_public_key
        self._nonce2 = None
        self._authenticated = False

    def phase1_respond(self, nonce1: str) -> str:
        print(f"[BADGE]   Received challenge: {nonce1}")
        mac = hmac.new(self.device_key, nonce1.encode(), hashlib.sha256).hexdigest()
        print(f"[BADGE]   Sending MAC: {mac[:16]}...")
        return mac

    def phase2_challenge(self) -> str:
        self._nonce2 = os.urandom(8).hex().upper()
        print(f"[BADGE]   Issuing reader challenge: {self._nonce2}")
        return self._nonce2

    def phase2_verify(self, signature: bytes) -> bool:
        try:
            self._signing_public_key.verify(signature, self._nonce2.encode())
            print("[BADGE]   Reader signature verified. ✓")
            self._authenticated = True
            return True
        except InvalidSignature:
            print("[BADGE]   Reader signature invalid. Rejecting.")
            return False

    def handle_command(self, command: str) -> str:
        if not self._authenticated:
            raise PermissionError("No authenticated session — complete mutual auth first")
        parts = command.strip().split()
        if parts[0] == "READ_SECTOR" and len(parts) == 2:
            data = {"0": "C0DECAFE", "1": "DEADBEEF", "2": "12345678"}
            return f"OK, data={data.get(parts[1], '00000000')}"
        return "ERROR, unknown command"
