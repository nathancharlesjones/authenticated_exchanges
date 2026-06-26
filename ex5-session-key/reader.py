import hmac
import hashlib
import os

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from derive_key import derive_key


def _session_key_from_dh(dh_secret: bytes, nonce_r: str, nonce_c: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=None,
        info=b"|".join([nonce_r.encode(), nonce_c.encode(), b"session"]),
    ).derive(dh_secret)


class Reader:
    def __init__(self, master_key: bytes, signing_private_key, dh_private_key):
        self.master_key = master_key
        self._signing_key = signing_private_key
        self._dh_private_key = dh_private_key

    def phase1_challenge(self) -> str:
        nonce1 = os.urandom(8).hex().upper()
        print(f"[READER] Sending challenge: {nonce1}")
        return nonce1

    def phase1_verify(self, uid: bytes, nonce1: str, mac: str) -> bool:
        device_key = derive_key(self.master_key, uid)
        expected = hmac.new(device_key, nonce1.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(mac, expected)

    def phase2_sign(self, nonce2: str) -> bytes:
        sig = self._signing_key.sign(nonce2.encode())
        print(f"[READER] Signing reader challenge: {sig.hex()[:16]}...")
        return sig

    def derive_session_key(self, uid: bytes, nonce_r: str, nonce_c: str, ephemeral_pub: bytes) -> bytes:
        """Receive badge's ephemeral X25519 public key, complete DH, derive session key."""
        ephemeral_public = X25519PublicKey.from_public_bytes(ephemeral_pub)
        dh_secret = self._dh_private_key.exchange(ephemeral_public)
        session_key = _session_key_from_dh(dh_secret, nonce_r, nonce_c)
        print(f"[READER] Session key derived (uid={uid.decode()}).")
        return session_key
