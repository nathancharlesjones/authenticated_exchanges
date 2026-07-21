from pathlib import Path

from channel import Channel

_DEFAULT_LOG = Path(__file__).parent / "logs" / "last_session.txt"


class Session:
    def __init__(self, reader, badge, log_path: Path = _DEFAULT_LOG):
        self.reader = reader
        self.badge = badge
        self.log_path = Path(log_path)

    def run(self) -> Channel | None:
        """
        Drives the two-phase mutual authentication exchange.

        Returns a Channel on success, None on any auth failure.
        """
        self._clear_log()
        print(f"[READER] Received UID: {self.badge.uid.decode()}")
        self._log(f"uid={self.badge.uid.decode()}")
        print("[READER] Phase 1: Authenticating badge...")

        nonce_r = self.reader.phase1_challenge()
        response_c = self.badge.phase1_respond(nonce_r)
        phase1_verified = self.reader.phase1_verify(self.badge.uid, nonce_r, response_c)
        self._log(f"nonce_r={nonce_r}")
        self._log(f"response_c={response_c}")
        self._log(f"phase1_verified={phase1_verified}")

        if not phase1_verified:
            print("[READER] Badge response incorrect.")
            print("[DOOR]   *** ACCESS DENIED ***")
            self._log("result=DENIED")
            return None

        print("[READER] Badge response verified. ✓")
        print("[READER] Phase 2: Authenticating reader to badge...")

        nonce_c = self.badge.phase2_challenge()
        response_r = self.reader.phase2_respond(nonce_c)
        badge_accepted = self.badge.phase2_verify(response_r)
        self._log(f"nonce_c={nonce_c}")
        self._log(f"response_r={response_r.hex()}")
        self._log(f"badge_accepted={badge_accepted}")

        if not badge_accepted:
            print("[BADGE]   *** READER NOT AUTHENTICATED ***")
            print("[DOOR]   *** ACCESS DENIED ***")
            self._log("result=DENIED")
            return None

        print("[DOOR]   *** ACCESS GRANTED ***")
        self._log("result=GRANTED")
        return Channel(self.reader, self.badge)

    def _clear_log(self):
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_path.write_text("")

    def _log(self, line: str):
        with self.log_path.open("a") as f:
            f.write(f"{line}\n")
