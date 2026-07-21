from pathlib import Path

from secure_channel import SecureChannel

_DEFAULT_LOG = Path(__file__).parent / "logs" / "last_session.txt"


class Session:
    def __init__(self, reader, badge, log_path: Path = _DEFAULT_LOG):
        self.reader = reader
        self.badge = badge
        self.log_path = Path(log_path)

    def establish(self):
        """
        Three-phase session establishment:
          Phase 1 — badge authenticates to reader (HMAC MAC)
          Phase 2 — reader authenticates to badge (Ed25519 signature)
          Phase 3 — reader looks up the badge's pre-shared info key (baked in at provisioning)
        Returns a SecureChannel on success, None on any auth failure.
        """
        self._clear_log()
        print(f"[READER] Received UID: {self.badge.uid.decode()}")
        self._log(f"uid={self.badge.uid.decode()}")
        print("[READER] Phase 1: Authenticating badge...")

        nonce1 = self.reader.phase1_challenge()
        mac = self.badge.phase1_respond(nonce1)
        phase1_verified = self.reader.phase1_verify(self.badge.uid, nonce1, mac)
        self._log(f"nonce1={nonce1}")
        self._log(f"mac={mac}")
        self._log(f"phase1_verified={phase1_verified}")

        if not phase1_verified:
            print("[READER] Badge MAC incorrect.")
            print("[DOOR]   *** ACCESS DENIED ***")
            self._log("result=DENIED")
            return None

        print("[READER] Badge MAC verified. ✓")
        print("[READER] Phase 2: Authenticating reader to badge...")

        nonce2 = self.badge.phase2_challenge()
        signature = self.reader.phase2_sign(nonce2)
        phase2_verified = self.badge.phase2_verify(signature)
        self._log(f"nonce2={nonce2}")
        self._log(f"signature={signature.hex()}")
        self._log(f"phase2_verified={phase2_verified}")

        if not phase2_verified:
            print("[BADGE]   *** READER NOT AUTHENTICATED — REFUSING FURTHER COMMUNICATION ***")
            self._log("result=DENIED")
            return None

        print("[READER] Phase 3: Looking up info key...")

        reader_info_key = self.reader.derive_info_key(self.badge.uid)

        # Both sides must arrive at the same info key; a mismatch indicates a bug.
        assert reader_info_key == self.badge.info_key, "Info key mismatch — protocol error"

        print("[DOOR]   *** ACCESS GRANTED ***")
        self._log("result=GRANTED")
        return SecureChannel(reader_info_key, self.reader, self.badge)

    def _clear_log(self):
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_path.write_text("")

    def _log(self, line: str):
        with self.log_path.open("a") as f:
            f.write(f"{line}\n")
