import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from derive_key import derive_key
from card import Card
from reader import Reader
from rogue_reader import RogueReader
from session import Session
from secure_channel import SecureChannel, encrypt, decrypt


MASTER = b"workshop_master_key"
UID       = b"A3F29C11"

# Reader key material: private keys stay on the reader; public keys are embedded
# in every badge at provisioning time.
_SIGNING_PRIVATE = Ed25519PrivateKey.generate()
_SIGNING_PUBLIC  = _SIGNING_PRIVATE.public_key()
_DH_PRIVATE      = X25519PrivateKey.generate()
_DH_PUBLIC       = _DH_PRIVATE.public_key()


def _make_reader():
    return Reader(MASTER, _SIGNING_PRIVATE, _DH_PRIVATE)


def _make_card():
    return Card(UID, derive_key(MASTER, UID), _SIGNING_PUBLIC, _DH_PUBLIC)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_establish_returns_secure_channel(tmp_path):
    ch = Session(_make_reader(), _make_card(), log_path=tmp_path / "last_session.txt").establish()
    assert isinstance(ch, SecureChannel)


def test_secure_channel_command_roundtrip(tmp_path):
    ch = Session(_make_reader(), _make_card(), log_path=tmp_path / "last_session.txt").establish()
    assert "DEADBEEF" in ch.send_command("READ_SECTOR 1")


def test_each_session_derives_fresh_key(tmp_path):
    # Ephemeral X25519 guarantees a unique DH secret — and thus a unique session key —
    # every time, even for the same badge presenting to the same reader.
    ch1 = Session(_make_reader(), _make_card(), log_path=tmp_path / "last_session.txt").establish()
    ch2 = Session(_make_reader(), _make_card(), log_path=tmp_path / "last_session.txt").establish()
    assert ch1.session_key != ch2.session_key


def test_same_nonces_different_ephemeral_keys_yield_different_session_keys(tmp_path):
    # Even when nonces are identical, two sessions differ because each session
    # generates a fresh ephemeral keypair. Patch os.urandom to fix nonce values
    # without fixing X25519PrivateKey.generate(), which uses the OS CSPRNG directly.
    from unittest.mock import patch
    fixed_nonce = bytes.fromhex("aabbccddaabbccdd")
    with patch("os.urandom", return_value=fixed_nonce):
        ch1 = Session(_make_reader(), _make_card(), log_path=tmp_path / "last_session.txt").establish()
        ch2 = Session(_make_reader(), _make_card(), log_path=tmp_path / "last_session.txt").establish()
    assert ch1.session_key != ch2.session_key


def test_wrong_dh_key_cannot_derive_session_key():
    # An eavesdropper with the wrong X25519 private key sees the ephemeral public
    # key in the clear but cannot reproduce the DH shared secret — and therefore
    # cannot derive the session key.
    card = _make_card()
    reader = _make_reader()

    # Run Phase 1 and 2 manually to reach an authenticated state.
    nonce_r = reader.phase1_challenge()
    mac = card.phase1_respond(nonce_r)
    assert reader.phase1_verify(card.uid, nonce_r, mac)
    nonce_c = card.phase2_challenge()
    sig = reader.phase2_sign(nonce_c)
    assert card.phase2_verify(sig)

    eph_pub = card.generate_ephemeral_keypair()
    card_sk = card.derive_session_key(nonce_r, nonce_c)

    # Impostor with a different X25519 private key cannot reproduce card_sk.
    impostor = Reader(MASTER, _SIGNING_PRIVATE, X25519PrivateKey.generate())
    impostor_sk = impostor.derive_session_key(card.uid, nonce_r, nonce_c, eph_pub)
    assert impostor_sk != card_sk


# ---------------------------------------------------------------------------
# Auth guards
# ---------------------------------------------------------------------------

def test_handle_command_requires_authenticated_session():
    with pytest.raises(PermissionError):
        _make_card().handle_command("READ_SECTOR 0")


def test_generate_ephemeral_keypair_requires_authenticated_session():
    with pytest.raises(PermissionError):
        _make_card().generate_ephemeral_keypair()


def test_rogue_reader_gets_none(tmp_path):
    ch = Session(RogueReader(), _make_card(), log_path=tmp_path / "last_session.txt").establish()
    assert ch is None


def test_wrong_master_key_gets_none(tmp_path):
    bad_reader = Reader(b"wrong_master_key", _SIGNING_PRIVATE, _DH_PRIVATE)
    ch = Session(bad_reader, _make_card(), log_path=tmp_path / "last_session.txt").establish()
    assert ch is None


def test_wrong_signing_key_gets_none(tmp_path):
    # A reader with a different Ed25519 private key cannot pass Phase 2 —
    # the badge's embedded public key will reject the signature.
    imposter = Reader(MASTER, Ed25519PrivateKey.generate(), _DH_PRIVATE)
    ch = Session(imposter, _make_card(), log_path=tmp_path / "last_session.txt").establish()
    assert ch is None


# ---------------------------------------------------------------------------
# Encryption properties
# ---------------------------------------------------------------------------

def test_each_session_produces_different_ciphertext(tmp_path):
    ch1 = Session(_make_reader(), _make_card(), log_path=tmp_path / "last_session.txt").establish()
    ch2 = Session(_make_reader(), _make_card(), log_path=tmp_path / "last_session.txt").establish()
    enc1 = encrypt(ch1.session_key, "READ_SECTOR 0")
    enc2 = encrypt(ch2.session_key, "READ_SECTOR 0")
    assert enc1 != enc2


def test_tampered_command_raises(tmp_path):
    from cryptography.exceptions import InvalidTag
    ch = Session(_make_reader(), _make_card(), log_path=tmp_path / "last_session.txt").establish()
    ciphertext = bytearray(encrypt(ch.session_key, "READ_SECTOR 0"))
    ciphertext[15] ^= 0xFF
    with pytest.raises(InvalidTag):
        decrypt(ch.session_key, bytes(ciphertext))


# ---------------------------------------------------------------------------
# Green (optional) exercises — skipped by default
# ---------------------------------------------------------------------------

@pytest.mark.skip(reason="Green exercise: implement session revocation")
class TestGreenExercise:
    def test_channel_unusable_after_explicit_close(self, tmp_path):
        ch = Session(_make_reader(), _make_card(), log_path=tmp_path / "last_session.txt").establish()
        ch.close()
        with pytest.raises(Exception):
            ch.send_command("READ_SECTOR 0")

    def test_second_establish_invalidates_first_channel(self, tmp_path):
        card = _make_card()
        reader = _make_reader()
        ch1 = Session(reader, card, log_path=tmp_path / "last_session.txt").establish()
        ch2 = Session(reader, card, log_path=tmp_path / "last_session.txt").establish()
        with pytest.raises(Exception):
            ch1.send_command("READ_SECTOR 0")
