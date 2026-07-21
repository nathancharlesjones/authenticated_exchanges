import hmac
import hashlib


def derive_key(fleet_key: bytes, uid: bytes, purpose: bytes) -> bytes:
    return hmac.new(fleet_key, uid.upper() + b"|" + purpose, hashlib.sha256).digest()
