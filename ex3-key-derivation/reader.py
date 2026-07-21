import hmac
import hashlib
import os
from pathlib import Path

from derive_key import derive_key

_DEFAULT_LOG = Path(__file__).parent / "logs" / "last_session.txt"


class Reader:
    def __init__(self, fleet_key: bytes, revoked: set = None, log_path: Path = _DEFAULT_LOG):
        self.fleet_key = fleet_key
        self.revoked = {uid.upper() for uid in (revoked or [])}
        self.log_path = Path(log_path)

    def present(self, badge) -> bool:
        self._clear_log()
        print(f"[READER] Received UID: {badge.uid.decode()}")

        if badge.uid in self.revoked:
            print("[READER] UID is revoked.")
            print("[DOOR]   *** ACCESS DENIED ***")
            return False

        nonce = os.urandom(8).hex().upper()
        print(f"[READER] Sending challenge: {nonce}")

        response = badge.respond(nonce)
        self._log(f"nonce={nonce}")
        self._log(f"response={response}")

        # badge_key = derive_key(  )
        # expected = hmac.new(   )

        if hmac.compare_digest(response, expected):
            print("[READER] Response verified.")
            print("[DOOR]   *** ACCESS GRANTED ***")
            return True
        else:
            print("[READER] Response incorrect.")
            print("[DOOR]   *** ACCESS DENIED ***")
            return False

    def _clear_log(self):
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_path.write_text("")

    def _log(self, line: str):
        with self.log_path.open("a") as f:
            f.write(f"{line}\n")
