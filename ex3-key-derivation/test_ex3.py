import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from unittest.mock import patch

import pytest
from derive_key import derive_key
from reader import Reader
from badge import Badge


FLEET = os.urandom(16)
UID_A = b"A3F29C11"
UID_B = b"B7E10422"


def _make_reader(log_path, revoked=None):
    return Reader(fleet_key=FLEET, revoked=revoked or set(), log_path=log_path)


def _parse_log(log_file):
    return dict(line.split("=", 1) for line in log_file.read_text().splitlines())


def test_two_badges_both_granted(log_path):
    reader = _make_reader(log_path)
    assert reader.present(Badge(uid=UID_A, key=derive_key(FLEET, UID_A))) is True
    assert reader.present(Badge(uid=UID_B, key=derive_key(FLEET, UID_B))) is True


def test_different_badges_respond_differently_to_same_nonce(log_path):
    fixed = bytes.fromhex("AABBCCDD11223344")

    with patch("os.urandom", return_value=fixed):
        Reader(fleet_key=FLEET, log_path=log_path).present(Badge(uid=UID_A, key=derive_key(FLEET, UID_A)))
        response_a = _parse_log(log_path)["response"]

        Reader(fleet_key=FLEET, log_path=log_path).present(Badge(uid=UID_B, key=derive_key(FLEET, UID_B)))
        response_b = _parse_log(log_path)["response"]

    assert response_a != response_b


def test_derived_keys_differ_per_uid():
    assert derive_key(FLEET, UID_A) != derive_key(FLEET, UID_B)


def test_derive_key_is_deterministic():
    assert derive_key(FLEET, UID_A) == derive_key(FLEET, UID_A)


def test_stolen_badge_key_cannot_clone_sibling(log_path):
    # Attacker extracts badge A's key and tries to authenticate as badge B.
    stolen_key = derive_key(FLEET, UID_A)
    imposter = Badge(uid=UID_B, key=stolen_key)
    assert _make_reader(log_path).present(imposter) is False


def test_fleet_key_compromise_covers_all_badges(log_path):
    # With the fleet key, any UID can be authenticated — blast radius is total.
    for uid in [UID_A, UID_B, b"FF00AA55", b"DEADBEEF"]:
        badge = Badge(uid=uid, key=derive_key(FLEET, uid))
        assert _make_reader(log_path).present(badge) is True


def test_revoked_badge_denied_despite_correct_key(log_path):
    badge = Badge(uid=UID_A, key=derive_key(FLEET, UID_A))
    assert _make_reader(log_path, revoked={UID_A}).present(badge) is False
