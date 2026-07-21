import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from derive_key import derive_key
from badge import Badge
from reader import Reader
from rogue_reader import RogueReader
from session import Session
from secure_channel import SecureChannel, encrypt, decrypt


FLEET = os.urandom(16)
UID   = b"A3F29C11"

# Reader key material: the signing private key stays on the reader; the
# matching public key is embedded in every badge at provisioning time.
_SIGNING_PRIVATE = Ed25519PrivateKey.generate()
_SIGNING_PUBLIC  = _SIGNING_PRIVATE.public_key()


def _make_reader():
    return Reader(FLEET, _SIGNING_PRIVATE)


def _make_badge():
    return Badge(
        UID,
        derive_key(FLEET, UID, b"badge_auth"),
        derive_key(FLEET, UID, b"info_encryption"),
        _SIGNING_PUBLIC,
    )


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_establish_returns_secure_channel(log_path):
    ch = Session(_make_reader(), _make_badge(), log_path=log_path).establish()
    assert isinstance(ch, SecureChannel)


def test_secure_channel_command_roundtrip(log_path):
    ch = Session(_make_reader(), _make_badge(), log_path=log_path).establish()
    assert "DEADBEEF" in ch.send_command("READ_SECTOR 1")


def test_same_badge_gets_same_info_key_every_session(log_path):
    # The info key is baked into the badge at provisioning time and looked up
    # (not exchanged) by the reader — so, unlike an ephemeral key exchange, it's
    # identical session after session for the same badge. That's the tradeoff
    # this exercise is about: no per-session freshness, no forward secrecy.
    ch1 = Session(_make_reader(), _make_badge(), log_path=log_path).establish()
    ch2 = Session(_make_reader(), _make_badge(), log_path=log_path).establish()
    assert ch1.info_key == ch2.info_key


def test_different_badges_get_different_info_keys(log_path):
    badge_a = _make_badge()
    badge_b = Badge(
        b"B4A0FF22",
        derive_key(FLEET, b"B4A0FF22", b"badge_auth"),
        derive_key(FLEET, b"B4A0FF22", b"info_encryption"),
        _SIGNING_PUBLIC,
    )
    assert badge_a.info_key != badge_b.info_key


# ---------------------------------------------------------------------------
# Auth guards
# ---------------------------------------------------------------------------

def test_handle_command_requires_authenticated_session():
    with pytest.raises(PermissionError):
        _make_badge().handle_command("READ_SECTOR 0")


def test_rogue_reader_gets_none(log_path):
    ch = Session(RogueReader(), _make_badge(), log_path=log_path).establish()
    assert ch is None


def test_wrong_fleet_key_gets_none(log_path):
    bad_reader = Reader(b"wrong_fleet_key", _SIGNING_PRIVATE)
    ch = Session(bad_reader, _make_badge(), log_path=log_path).establish()
    assert ch is None


def test_wrong_signing_key_gets_none(log_path):
    # A reader with a different Ed25519 private key cannot pass Phase 2 —
    # the badge's embedded public key will reject the signature.
    imposter = Reader(FLEET, Ed25519PrivateKey.generate())
    ch = Session(imposter, _make_badge(), log_path=log_path).establish()
    assert ch is None


# ---------------------------------------------------------------------------
# Encryption properties
# ---------------------------------------------------------------------------

def test_same_info_key_still_produces_different_ciphertext(log_path):
    # Even though the info key is identical every session, AES-GCM's random IV
    # means two encryptions of the same plaintext under the same key still differ.
    ch1 = Session(_make_reader(), _make_badge(), log_path=log_path).establish()
    ch2 = Session(_make_reader(), _make_badge(), log_path=log_path).establish()
    enc1 = encrypt(ch1.info_key, "READ_SECTOR 0")
    enc2 = encrypt(ch2.info_key, "READ_SECTOR 0")
    assert enc1 != enc2


def test_tampered_command_raises(log_path):
    from cryptography.exceptions import InvalidTag
    ch = Session(_make_reader(), _make_badge(), log_path=log_path).establish()
    ciphertext = bytearray(encrypt(ch.info_key, "READ_SECTOR 0"))
    ciphertext[15] ^= 0xFF
    with pytest.raises(InvalidTag):
        decrypt(ch.info_key, bytes(ciphertext))


# ---------------------------------------------------------------------------
# Green (optional) exercises — skipped by default
# ---------------------------------------------------------------------------

@pytest.mark.skip(reason="Green exercise: implement session revocation")
class TestGreenExercise:
    def test_channel_unusable_after_explicit_close(self, log_path):
        ch = Session(_make_reader(), _make_badge(), log_path=log_path).establish()
        ch.close()
        with pytest.raises(Exception):
            ch.send_command("READ_SECTOR 0")

    def test_second_establish_invalidates_first_channel(self, log_path):
        badge = _make_badge()
        reader = _make_reader()
        ch1 = Session(reader, badge, log_path=log_path).establish()
        ch2 = Session(reader, badge, log_path=log_path).establish()
        with pytest.raises(Exception):
            ch1.send_command("READ_SECTOR 0")
