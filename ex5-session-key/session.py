from secure_channel import SecureChannel


class Session:
    def __init__(self, reader, card):
        self.reader = reader
        self.card = card

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

        if not self.reader.phase1_verify(self.card.uid, nonce1, mac):
            print("[READER] Badge MAC incorrect.")
            print("[DOOR]   *** ACCESS DENIED ***")
            return None

        print("[READER] Badge MAC verified. ✓")
        print("[READER] Phase 2: Authenticating reader to badge...")

        nonce2 = self.card.phase2_challenge()
        signature = self.reader.phase2_sign(nonce2)

        if not self.card.phase2_verify(signature):
            print("[CARD]   *** READER NOT AUTHENTICATED — REFUSING FURTHER COMMUNICATION ***")
            return None

        print("[READER] Phase 3: Ephemeral X25519 key exchange...")

        ephemeral_pub = self.card.generate_ephemeral_keypair()
        card_session_key = self.card.derive_session_key(nonce1, nonce2)
        reader_session_key = self.reader.derive_session_key(self.card.uid, nonce1, nonce2, ephemeral_pub)

        # Both sides must arrive at the same session key; a mismatch indicates a bug.
        assert card_session_key == reader_session_key, "Session key mismatch — protocol error"

        print("[DOOR]   *** ACCESS GRANTED ***")
        return SecureChannel(reader_session_key, self.reader, self.card)
