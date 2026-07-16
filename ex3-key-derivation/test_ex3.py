import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from unittest.mock import patch

import pytest
from derive_key import derive_key
from reader import Reader
from card import Card


MASTER = b"workshop_master_key"
UID_A = b"A3F29C11"
UID_B = b"B7E10422"


def _make_reader(tmp_path, revoked=None):
    return Reader(master_key=MASTER, revoked=revoked or set(), log_path=tmp_path / "last_session.txt")


def _parse_log(log_file):
    return dict(line.split("=", 1) for line in log_file.read_text().splitlines())


# --- Red exercise ---

def test_two_cards_both_granted(tmp_path):
    reader = _make_reader(tmp_path)
    assert reader.present(Card(uid=UID_A, key=derive_key(MASTER, UID_A))) is True
    assert reader.present(Card(uid=UID_B, key=derive_key(MASTER, UID_B))) is True


def test_different_cards_respond_differently_to_same_nonce(tmp_path):
    log_file = tmp_path / "last_session.txt"
    fixed = bytes.fromhex("AABBCCDD11223344")

    with patch("os.urandom", return_value=fixed):
        Reader(master_key=MASTER, log_path=log_file).present(Card(uid=UID_A, key=derive_key(MASTER, UID_A)))
        response_a = _parse_log(log_file)["response"]

        Reader(master_key=MASTER, log_path=log_file).present(Card(uid=UID_B, key=derive_key(MASTER, UID_B)))
        response_b = _parse_log(log_file)["response"]

    assert response_a != response_b


# --- Yellow exercise ---

def test_derived_keys_differ_per_uid():
    assert derive_key(MASTER, UID_A) != derive_key(MASTER, UID_B)


def test_derive_key_is_deterministic():
    assert derive_key(MASTER, UID_A) == derive_key(MASTER, UID_A)


def test_stolen_card_key_cannot_clone_sibling(tmp_path):
    # Attacker extracts card A's key and tries to authenticate as card B.
    stolen_key = derive_key(MASTER, UID_A)
    imposter = Card(uid=UID_B, key=stolen_key)
    assert _make_reader(tmp_path).present(imposter) is False


def test_master_key_compromise_covers_all_cards(tmp_path):
    # With the master key, any UID can be authenticated — blast radius is total.
    for uid in [UID_A, UID_B, b"FF00AA55", b"DEADBEEF"]:
        card = Card(uid=uid, key=derive_key(MASTER, uid))
        assert _make_reader(tmp_path).present(card) is True


def test_revoked_card_denied_despite_correct_key(tmp_path):
    card = Card(uid=UID_A, key=derive_key(MASTER, UID_A))
    assert _make_reader(tmp_path, revoked={UID_A}).present(card) is False


# --- Green exercise ---
# To enable: remove the pytestmark line from TestGreenExercise below.

class TestGreenExercise:
    pytestmark = pytest.mark.skip(reason="Green exercise: provision FF00AA55 and experiment with revocation first")

    def test_new_card_provisioned(self, tmp_path):
        raise NotImplementedError

    def test_revoked_new_card_denied(self, tmp_path):
        raise NotImplementedError
