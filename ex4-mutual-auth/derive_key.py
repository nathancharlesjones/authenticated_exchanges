import hmac
import hashlib


def derive_key(fleet_key: bytes, uid: bytes) -> bytes:
    return hmac.new(fleet_key, uid.upper(), hashlib.sha256).digest()
