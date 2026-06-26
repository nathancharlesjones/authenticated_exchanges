class Session:
    def __init__(self, reader, card):
        self.reader = reader
        self.card = card

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

        if not self.reader.phase1_verify(self.card.uid, nonce_r, response_c):
            print("[READER] Card response incorrect.")
            print("[DOOR]   *** ACCESS DENIED ***")
            return False, None

        print("[READER] Card response verified. ✓")
        print("[READER] Phase 2: Authenticating reader to card...")

        nonce_c = self.card.phase2_challenge()
        response_r = self.reader.phase2_respond(nonce_c)
        card_accepted = self.card.phase2_verify(response_r)

        if not card_accepted:
            print("[CARD]   *** READER NOT AUTHENTICATED ***")
            print("[DOOR]   *** ACCESS DENIED ***")
            return False, False

        print("[DOOR]   *** ACCESS GRANTED ***")
        return True, True
