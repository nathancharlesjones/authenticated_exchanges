import hmac
import hashlib
import os

from cryptography.exceptions import InvalidSignature


class Badge:
    def __init__(self, uid: bytes, badge_key: bytes, reader_public_key):
        self.uid = uid.upper()
        self.badge_key = badge_key
        self._reader_public_key = reader_public_key
        self._nonce_c = None
        self._authenticated = False

    def phase1_respond(self, nonce_r: str) -> str:
        # Replace with `raise NotImplementedError` for actual exercise
        print(f"[BADGE]   Received challenge: {nonce_r}")
        response = hmac.new(self.badge_key, nonce_r.encode(), hashlib.sha256).hexdigest()
        print(f"[BADGE]   Sending response:   {response[:16]}...")
        return response

    def phase2_challenge(self) -> str:
        # Replace with `raise NotImplementedError` for actual exercise
        self._nonce_c = os.urandom(8).hex().upper()
        print(f"[BADGE]   Issuing reader challenge: {self._nonce_c}")
        return self._nonce_c

    def phase2_verify(self, signature: bytes) -> bool:
        # Replace with `raise NotImplementedError` for actual exercise
        try:
            self._reader_public_key.verify(signature, self._nonce_c.encode())
            self._authenticated = True
            print("[BADGE]   Reader signature verified. ✓")
            return True
        except InvalidSignature:
            print("[BADGE]   Reader signature invalid. Rejecting.")
            return False

    def handle_command(self, command: str) -> str:
        if not self._authenticated:
            raise PermissionError("No authenticated session — complete mutual auth first")
        parts = command.strip().split()
        if parts[0] == "READ_SECTOR" and len(parts) == 2:
            data = {"0": "CAFEBABE", "1": "DEADBEEF", "2": "12345678"}
            return f"OK, data={data.get(parts[1], '00000000')}"
        return "ERROR, unknown command"
