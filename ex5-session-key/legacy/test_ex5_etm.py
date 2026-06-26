import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

import pytest
from session_etm import encrypt, decrypt


KEY = b"\x00" * 16


def test_etm_roundtrip():
    assert decrypt(KEY, encrypt(KEY, "READ_SECTOR 0")) == "READ_SECTOR 0"


def test_etm_ciphertext_not_plaintext():
    assert b"READ_SECTOR 0" not in encrypt(KEY, "READ_SECTOR 0")


def test_etm_fresh_ciphertext_each_call():
    assert encrypt(KEY, "READ_SECTOR 0") != encrypt(KEY, "READ_SECTOR 0")


def test_etm_wrong_key_fails():
    ciphertext = encrypt(KEY, "READ_SECTOR 0")
    with pytest.raises(ValueError):
        decrypt(b"\xff" * 16, ciphertext)


def test_etm_tampered_ciphertext_fails():
    data = bytearray(encrypt(KEY, "READ_SECTOR 0"))
    data[20] ^= 0xFF
    with pytest.raises(ValueError):
        decrypt(KEY, bytes(data))
