from pathlib import Path

_DEFAULT_LOG = Path(__file__).parent / "logs" / "last_session.txt"


class Session:
    def __init__(self, reader, card, log_path: Path = _DEFAULT_LOG):
        self.reader = reader
        self.card = card
        self.log_path = Path(log_path)

    def run(self) -> tuple[bool, bool | None]:
        """
        Drives the two-phase mutual authentication exchange.

        Returns (door_granted, card_accepted_reader).
        card_accepted_reader is None when Phase 1 fails and Phase 2 never runs.
        """
        print(f"[READER] Received UID: {self.card.uid.decode()}")
        print("[READER] Phase 1: Authenticating card...")

        nonce_r = self.reader.phase1_challenge()
        response_c = self.card.phase1_respond(nonce_r)
        phase1_verified = self.reader.phase1_verify(self.card.uid, nonce_r, response_c)

        if not phase1_verified:
            print("[READER] Card response incorrect.")
            print("[DOOR]   *** ACCESS DENIED ***")
            self._log(nonce_r, response_c, phase1_verified, None, None, None, "DENIED")
            return False, None

        print("[READER] Card response verified. ✓")
        print("[READER] Phase 2: Authenticating reader to card...")

        nonce_c = self.card.phase2_challenge()
        response_r = self.reader.phase2_respond(nonce_c)
        card_accepted = self.card.phase2_verify(response_r)

        if not card_accepted:
            print("[CARD]   *** READER NOT AUTHENTICATED ***")
            print("[DOOR]   *** ACCESS DENIED ***")
            self._log(nonce_r, response_c, phase1_verified, nonce_c, response_r, card_accepted, "DENIED")
            return False, False

        print("[DOOR]   *** ACCESS GRANTED ***")
        self._log(nonce_r, response_c, phase1_verified, nonce_c, response_r, card_accepted, "GRANTED")
        return True, True

    def _log(self, nonce_r, response_c, phase1_verified, nonce_c, response_r, card_accepted, result):
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("w") as f:
            f.write(f"uid={self.card.uid.decode()}\n")
            f.write(f"nonce_r={nonce_r}\n")
            f.write(f"response_c={response_c}\n")
            f.write(f"phase1_verified={phase1_verified}\n")
            if nonce_c is not None:
                f.write(f"nonce_c={nonce_c}\n")
                f.write(f"response_r={response_r.hex()}\n")
                f.write(f"card_accepted={card_accepted}\n")
            f.write(f"result={result}\n")
