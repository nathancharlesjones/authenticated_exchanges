import hmac
import hashlib


def derive_key(master_key: bytes, uid: bytes) -> bytes:
    return hmac.new(master_key, uid.upper(), hashlib.sha256).digest()
