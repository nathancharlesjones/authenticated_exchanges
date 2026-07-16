from pathlib import Path

from secure_channel import SecureChannel

_DEFAULT_LOG = Path(__file__).parent / "logs" / "last_session.txt"


class Session:
    def __init__(self, reader, card, log_path: Path = _DEFAULT_LOG):
        self.reader = reader
        self.card = card
        self.log_path = Path(log_path)

    def establish(self):
        """
        Three-phase session establishment:
          Phase 1 — badge authenticates to reader (HMAC MAC)
          Phase 2 — reader authenticates to badge (Ed25519 signature)
          Phase 3 — ephemeral X25519 key exchange; both sides derive the session key via HKDF
        Returns a SecureChannel on success, None on any auth failure.
        """
        print(f"[READER] Received UID: {self.card.uid.decode()}")
        print("[READER] Phase 1: Authenticating badge...")

        nonce1 = self.reader.phase1_challenge()
        mac = self.card.phase1_respond(nonce1)
        phase1_verified = self.reader.phase1_verify(self.card.uid, nonce1, mac)

        if not phase1_verified:
            print("[READER] Badge MAC incorrect.")
            print("[DOOR]   *** ACCESS DENIED ***")
            self._log(nonce1, mac, phase1_verified, None, None, None, "DENIED")
            return None

        print("[READER] Badge MAC verified. ✓")
        print("[READER] Phase 2: Authenticating reader to badge...")

        nonce2 = self.card.phase2_challenge()
        signature = self.reader.phase2_sign(nonce2)
        phase2_verified = self.card.phase2_verify(signature)

        if not phase2_verified:
            print("[CARD]   *** READER NOT AUTHENTICATED — REFUSING FURTHER COMMUNICATION ***")
            self._log(nonce1, mac, phase1_verified, nonce2, signature, phase2_verified, "DENIED")
            return None

        print("[READER] Phase 3: Ephemeral X25519 key exchange...")

        ephemeral_pub = self.card.generate_ephemeral_keypair()
        card_session_key = self.card.derive_session_key(nonce1, nonce2)
        reader_session_key = self.reader.derive_session_key(self.card.uid, nonce1, nonce2, ephemeral_pub)

        # Both sides must arrive at the same session key; a mismatch indicates a bug.
        assert card_session_key == reader_session_key, "Session key mismatch — protocol error"

        print("[DOOR]   *** ACCESS GRANTED ***")
        self._log(nonce1, mac, phase1_verified, nonce2, signature, phase2_verified, "GRANTED")
        return SecureChannel(reader_session_key, self.reader, self.card)

    def _log(self, nonce1, mac, phase1_verified, nonce2, signature, phase2_verified, result):
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("w") as f:
            f.write(f"uid={self.card.uid.decode()}\n")
            f.write(f"nonce1={nonce1}\n")
            f.write(f"mac={mac}\n")
            f.write(f"phase1_verified={phase1_verified}\n")
            if nonce2 is not None:
                f.write(f"nonce2={nonce2}\n")
                f.write(f"signature={signature.hex()}\n")
                f.write(f"phase2_verified={phase2_verified}\n")
            f.write(f"result={result}\n")
