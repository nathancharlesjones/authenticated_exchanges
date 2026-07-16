import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

import hmac
import hashlib
from unittest.mock import patch

import pytest
from reader import Reader
from card import Card, compute_response


KEY = b"workshop_key_do_not_use"
UID = b"A3F29C11"


def _make_reader(tmp_path):
    return Reader(keys={UID: KEY}, log_path=tmp_path / "last_session.txt")


def _parse_log(log_file):
    return dict(line.split("=", 1) for line in log_file.read_text().splitlines())


# --- Red exercise ---

def test_correct_key_grants_access(tmp_path):
    result = _make_reader(tmp_path).present(Card(uid=UID, key=KEY))

    assert result is True
    fields = _parse_log(tmp_path / "last_session.txt")
    assert fields["uid"] == UID.decode()
    assert "nonce" in fields
    assert fields["result"] == "GRANTED"


def test_challenge_is_random(tmp_path):
    log_file = tmp_path / "last_session.txt"
    reader = Reader(keys={UID: KEY}, log_path=log_file)
    card = Card(uid=UID, key=KEY)

    reader.present(card)
    nonce1 = _parse_log(log_file)["nonce"]
    reader.present(card)
    nonce2 = _parse_log(log_file)["nonce"]

    assert nonce1 != nonce2


def test_response_changes_with_challenge(tmp_path):
    log_file = tmp_path / "last_session.txt"
    reader = Reader(keys={UID: KEY}, log_path=log_file)
    card = Card(uid=UID, key=KEY)

    reader.present(card)
    response1 = _parse_log(log_file)["response"]
    reader.present(card)
    response2 = _parse_log(log_file)["response"]

    assert response1 != response2


# --- Yellow exercise ---

def test_wrong_key_denies_access(tmp_path):
    result = _make_reader(tmp_path).present(Card(uid=UID, key=b"wrong_key"))

    assert result is False
    assert _parse_log(tmp_path / "last_session.txt")["result"] == "DENIED"


def test_wrong_key_response_is_completely_different():
    # Avalanche effect: flipping a bit in the key scrambles the entire output.
    nonce = "AABBCCDD11223344"
    correct = compute_response(KEY, nonce)
    wrong = compute_response(b"wrong_key", nonce)
    assert correct != wrong
    # Sanity-check that neither is suspiciously close to the other.
    matching = sum(a == b for a, b in zip(correct, wrong))
    assert matching < len(correct) // 4


def test_replay_attack_denied(tmp_path):
    log_file = tmp_path / "last_session.txt"
    reader = Reader(keys={UID: KEY}, log_path=log_file)

    reader.present(Card(uid=UID, key=KEY))
    captured_response = _parse_log(log_file)["response"]

    class ReplayCard:
        uid = UID
        def respond(self, nonce):
            return captured_response

    assert reader.present(ReplayCard()) is False


def test_session_log_written(tmp_path):
    log_file = tmp_path / "last_session.txt"
    Reader(keys={UID: KEY}, log_path=log_file).present(Card(uid=UID, key=KEY))

    assert log_file.exists()
    fields = _parse_log(log_file)
    assert "nonce" in fields
    assert "response" in fields
    assert fields["result"] == "GRANTED"


# --- Green exercise (card_skeleton.py) ---
# To enable: remove the pytestmark line from TestGreenExercise below.

class TestGreenExercise:
    pytestmark = pytest.mark.skip(reason="Green exercise: fill in compute_response() in card_skeleton.py first")

    def test_skeleton_compute_response_known_vector(self):
        from card_skeleton import compute_response as skeleton_fn
        expected = hmac.new(KEY, b"AABBCCDD11223344", hashlib.sha256).hexdigest()
        assert skeleton_fn(KEY, "AABBCCDD11223344") == expected

    def test_skeleton_compute_response_is_hex(self):
        from card_skeleton import compute_response as skeleton_fn
        result = skeleton_fn(KEY, "AABBCCDD11223344")
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_skeleton_passes_reader_verification(self, tmp_path):
        from card_skeleton import Card as SkeletonCard
        result = _make_reader(tmp_path).present(SkeletonCard(uid=UID, key=KEY))
        assert result is True
