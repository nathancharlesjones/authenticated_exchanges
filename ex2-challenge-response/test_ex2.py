import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

import hmac
import hashlib
from unittest.mock import patch

import pytest
from reader import Reader
from badge import Badge, compute_response


KEY = os.urandom(16)
UID = b"A3F29C11"


def _make_reader(log_path):
    return Reader(key=KEY, allowlist=[UID], log_path=log_path)


def _parse_log(log_file):
    return dict(line.split("=", 1) for line in log_file.read_text().splitlines())


# --- Red exercise ---

def test_correct_key_grants_access(log_path):
    result = _make_reader(log_path).present(Badge(uid=UID, key=KEY))

    assert result is True
    fields = _parse_log(log_path)
    assert fields["uid"] == UID.decode()
    assert "nonce" in fields
    assert fields["result"] == "GRANTED"


def test_challenge_is_random(log_path):
    reader = _make_reader(log_path)
    badge = Badge(uid=UID, key=KEY)

    reader.present(badge)
    nonce1 = _parse_log(log_path)["nonce"]
    reader.present(badge)
    nonce2 = _parse_log(log_path)["nonce"]

    assert nonce1 != nonce2


def test_response_changes_with_challenge(log_path):
    reader = _make_reader(log_path)
    badge = Badge(uid=UID, key=KEY)

    reader.present(badge)
    response1 = _parse_log(log_path)["response"]
    reader.present(badge)
    response2 = _parse_log(log_path)["response"]

    assert response1 != response2


def test_wrong_key_denies_access(log_path):
    result = _make_reader(log_path).present(Badge(uid=UID, key=b"wrong_key"))

    assert result is False
    assert _parse_log(log_path)["result"] == "DENIED"


def test_wrong_key_response_is_completely_different():
    # Avalanche effect: flipping a bit in the key scrambles the entire output.
    nonce = "AABBCCDD11223344"
    correct = compute_response(KEY, nonce)
    wrong = compute_response(b"wrong_key", nonce)
    assert correct != wrong
    # Sanity-check that neither is suspiciously close to the other.
    matching = sum(a == b for a, b in zip(correct, wrong))
    assert matching < len(correct) // 4


def test_session_log_written(log_path):
    _make_reader(log_path).present(Badge(uid=UID, key=KEY))

    assert log_path.exists()
    fields = _parse_log(log_path)
    assert "nonce" in fields
    assert "response" in fields
    assert fields["result"] == "GRANTED"
    

# --- Yellow exercise ---

def test_replay_attack_denied(log_path):
    reader = # ???

    captured_response = # ???

    class ReplayBadge:
        def __init__(self, uid: bytes, response: bytes):
            self.uid = uid
            self.response = response
        def respond(self, nonce):
            return self.response

    assert reader.present(ReplayBadge(UID, captured_response)) is False
