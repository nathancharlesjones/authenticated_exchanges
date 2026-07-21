import hmac
import hashlib
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def _session_key_from_dh(dh_secret: bytes, nonce_r: str, nonce_c: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=None,
        info=b"|".join([nonce_r.encode(), nonce_c.encode(), b"session"]),
    ).derive(dh_secret)


class Card:
    def __init__(self, uid: bytes, device_key: bytes, signing_public_key, dh_public_key):
        self.uid = uid.upper()
        self.device_key = device_key
        self._signing_public_key = signing_public_key
        self._dh_public_key = dh_public_key
        self._nonce2 = None
        self._authenticated = False
        self._ephemeral_private = None

    def phase1_respond(self, nonce1: str) -> str:
        print(f"[CARD]   Received challenge: {nonce1}")
        mac = hmac.new(self.device_key, nonce1.encode(), hashlib.sha256).hexdigest()
        print(f"[CARD]   Sending MAC: {mac[:16]}...")
        return mac

    def phase2_challenge(self) -> str:
        self._nonce2 = os.urandom(8).hex().upper()
        print(f"[CARD]   Issuing reader challenge: {self._nonce2}")
        return self._nonce2

    def phase2_verify(self, signature: bytes) -> bool:
        try:
            self._signing_public_key.verify(signature, self._nonce2.encode())
            print("[CARD]   Reader signature verified. ✓")
            self._authenticated = True
            return True
        except InvalidSignature:
            print("[CARD]   Reader signature invalid. Rejecting.")
            return False

    def generate_ephemeral_keypair(self) -> bytes:
        """Generate a fresh ephemeral X25519 key pair. Returns the public key bytes.
        The ephemeral private key is stored internally for use by derive_session_key()."""
        if not self._authenticated:
            raise PermissionError("Reader not authenticated — Phase 2 must succeed first")
        self._ephemeral_private = X25519PrivateKey.generate()
        eph_pub_bytes = self._ephemeral_private.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        print(f"[CARD]   Generated ephemeral public key: {eph_pub_bytes.hex()[:16]}...")
        return eph_pub_bytes

    def derive_session_key(self, nonce_r: str, nonce_c: str) -> bytes:
        """Complete the X25519 exchange and derive the session key via HKDF."""
        if self._ephemeral_private is None:
            raise PermissionError("generate_ephemeral_keypair() must be called first")
        dh_secret = self._ephemeral_private.exchange(self._dh_public_key)
        session_key = _session_key_from_dh(dh_secret, nonce_r, nonce_c)
        print("[CARD]   Session key derived.")
        return session_key

    def handle_command(self, command: str) -> str:
        if not self._authenticated:
            raise PermissionError("No authenticated session — complete mutual auth first")
        parts = command.strip().split()
        if parts[0] == "READ_SECTOR" and len(parts) == 2:
            data = {"0": "CAFEBABE", "1": "DEADBEEF", "2": "12345678"}
            return f"OK, data={data.get(parts[1], '00000000')}"
        return "ERROR, unknown command"
