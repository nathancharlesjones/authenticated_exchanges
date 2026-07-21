import hmac
import hashlib
import os
from pathlib import Path

_DEFAULT_LOG = Path(__file__).parent / "logs" / "last_session.txt"


class Reader:
    def __init__(self, key: bytes, allowlist: list, log_path: Path = _DEFAULT_LOG):
        self.key = key
        self.allowlist = allowlist
        self.log_path = Path(log_path)

    def present(self, badge) -> bool:
        self._clear_log()
        print(f"[READER] Received UID: {badge.uid.decode()}")
        self._log(f"uid={badge.uid.decode()}")

        if badge.uid not in self.allowlist:
            print("[READER] UID not recognized.")
            print("[DOOR]   *** ACCESS DENIED ***")
            self._log("result=DENIED")
            return False

        nonce = os.urandom(8).hex().upper()
        print(f"[READER] Sending challenge: {nonce}")
        self._log(f"nonce={nonce}")

        response = badge.respond(nonce)
        self._log(f"response={response}")
        expected = hmac.new(self.key, nonce.encode(), hashlib.sha256).hexdigest()
        granted = hmac.compare_digest(response, expected)

        if granted:
            print("[READER] Response verified.")
            print("[DOOR]   *** ACCESS GRANTED ***")
        else:
            print("[READER] Response incorrect.")
            print("[DOOR]   *** ACCESS DENIED ***")

        self._log(f"result={'GRANTED' if granted else 'DENIED'}")
        return granted

    def _clear_log(self):
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_path.write_text("")

    def _log(self, line: str):
        with self.log_path.open("a") as f:
            f.write(f"{line}\n")
