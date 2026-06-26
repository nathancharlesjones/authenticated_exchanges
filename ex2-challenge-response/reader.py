import hmac
import hashlib
import os
from pathlib import Path

_DEFAULT_LOG = Path(__file__).parent / "logs" / "last_session.txt"


class Reader:
    def __init__(self, keys: dict, log_path: Path = _DEFAULT_LOG):
        self.keys = {uid.upper(): key for uid, key in keys.items()}
        self.log_path = Path(log_path)

    def present(self, card) -> bool:
        print(f"[READER] Received UID: {card.uid.decode()}")

        if card.uid not in self.keys:
            print("[READER] UID not recognized.")
            print("[DOOR]   *** ACCESS DENIED ***")
            return False

        nonce = os.urandom(8).hex().upper()
        print(f"[READER] Sending challenge: {nonce}")

        response = card.respond(nonce)
        self._log(nonce, response)

        expected = hmac.new(self.keys[card.uid], nonce.encode(), hashlib.sha256).hexdigest()
        if hmac.compare_digest(response, expected):
            print("[READER] Response verified.")
            print("[DOOR]   *** ACCESS GRANTED ***")
            return True
        else:
            print("[READER] Response incorrect.")
            print("[DOOR]   *** ACCESS DENIED ***")
            return False

    def _log(self, nonce: str, response: str):
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("w") as f:
            f.write(f"nonce={nonce}\n")
            f.write(f"response={response}\n")
