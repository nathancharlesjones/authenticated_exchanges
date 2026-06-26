import os


class RogueReader:
    """
    A reader with no legitimate private key.
    Accepts all cards in Phase 1 (harvesting their responses),
    but cannot produce a valid signature for the card's Phase 2 challenge.
    """

    def phase1_challenge(self) -> str:
        nonce_r = os.urandom(8).hex().upper()
        print(f"[ROGUE]  Sending challenge: {nonce_r}")
        return nonce_r

    def phase1_verify(self, uid: bytes, nonce_r: str, response_c: str) -> bool:
        print(f"[ROGUE]  Phase 1 response captured: {response_c[:16]}...")
        return True

    def phase2_respond(self, nonce_c: str) -> bytes:
        print("[ROGUE]  Cannot sign Phase 2 challenge (no private key).")
        return b""
