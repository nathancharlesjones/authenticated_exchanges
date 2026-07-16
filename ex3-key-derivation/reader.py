import hmac
import hashlib
import os
from pathlib import Path

from derive_key import derive_key

_DEFAULT_LOG = Path(__file__).parent / "logs" / "last_session.txt"


class Reader:
    def __init__(self, master_key: bytes, revoked: set = None, log_path: Path = _DEFAULT_LOG):
        self.master_key = master_key
        self.revoked = {uid.upper() for uid in (revoked or [])}
        self.log_path = Path(log_path)

    def present(self, card) -> bool:
        print(f"[READER] Received UID: {card.uid.decode()}")

        if card.uid in self.revoked:
            print("[READER] UID is revoked.")
            print("[DOOR]   *** ACCESS DENIED ***")
            return False

        nonce = os.urandom(8).hex().upper()
        print(f"[READER] Sending challenge: {nonce}")

        response = card.respond(nonce)
        self._log(nonce, response)

        # card_key = derive_key(  )
        # expected = hmac.new(   )

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
