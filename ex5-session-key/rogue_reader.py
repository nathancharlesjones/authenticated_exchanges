import os


class RogueReader:
    """
    A reader with no private keys.
    Accepts all badges in Phase 1 (harvesting their MACs),
    but cannot produce a valid Ed25519 signature for Phase 2,
    so it never reaches Phase 3 and never learns the badge's info key.
    """

    def phase1_challenge(self) -> str:
        nonce1 = os.urandom(8).hex().upper()
        print(f"[ROGUE]  Sending challenge: {nonce1}")
        return nonce1

    def phase1_verify(self, uid: bytes, nonce1: str, mac: str) -> bool:
        print(f"[ROGUE]  Phase 1 MAC captured: {mac[:16]}...")
        return True

    def phase2_sign(self, nonce2: str) -> bytes:
        print("[ROGUE]  Cannot sign Phase 2 challenge (no private key).")
        return b""
