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
            self._log(card.uid, None, None, "DENIED")
            return False

        nonce = os.urandom(8).hex().upper()
        print(f"[READER] Sending challenge: {nonce}")

        response = card.respond(nonce)
        expected = hmac.new(self.keys[card.uid], nonce.encode(), hashlib.sha256).hexdigest()
        granted = hmac.compare_digest(response, expected)

        if granted:
            print("[READER] Response verified.")
            print("[DOOR]   *** ACCESS GRANTED ***")
        else:
            print("[READER] Response incorrect.")
            print("[DOOR]   *** ACCESS DENIED ***")

        self._log(card.uid, nonce, response, "GRANTED" if granted else "DENIED")
        return granted

    def _log(self, uid: bytes, nonce, response, result: str):
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("w") as f:
            f.write(f"uid={uid.decode()}\n")
            if nonce is not None:
                f.write(f"nonce={nonce}\n")
                f.write(f"response={response}\n")
            f.write(f"result={result}\n")
