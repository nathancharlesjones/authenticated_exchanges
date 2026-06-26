import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from cryptography.exceptions import InvalidTag
from secure_channel import encrypt, decrypt


KEY = b"\x00" * 16


def test_gcm_roundtrip():
    assert decrypt(KEY, encrypt(KEY, "READ_SECTOR 0")) == "READ_SECTOR 0"


def test_gcm_ciphertext_not_plaintext():
    assert b"READ_SECTOR 0" not in encrypt(KEY, "READ_SECTOR 0")


def test_gcm_fresh_ciphertext_each_call():
    assert encrypt(KEY, "READ_SECTOR 0") != encrypt(KEY, "READ_SECTOR 0")


def test_gcm_wrong_key_fails():
    ciphertext = encrypt(KEY, "READ_SECTOR 0")
    with pytest.raises(InvalidTag):
        decrypt(b"\xff" * 16, ciphertext)


def test_gcm_tampered_ciphertext_fails():
    data = bytearray(encrypt(KEY, "READ_SECTOR 0"))
    data[15] ^= 0xFF
    with pytest.raises(InvalidTag):
        decrypt(KEY, bytes(data))
