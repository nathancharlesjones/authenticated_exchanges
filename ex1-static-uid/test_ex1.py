import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from reader import Reader
from card import Card


def _parse_log(log_file):
    return [line.split(",") for line in log_file.read_text().splitlines()]


def test_known_uid_grants_access(tmp_path):
    log_file = tmp_path / "observed_uids.txt"
    reader = Reader(allowlist=[b"A3F29C11", b"B7E10422"], log_path=log_file)
    result = reader.present(Card(uid=b"A3F29C11"))

    assert result is True
    uid, status = _parse_log(log_file)[0]
    assert uid == "A3F29C11"
    assert status == "GRANTED"


def test_unknown_uid_denies_access(tmp_path):
    log_file = tmp_path / "observed_uids.txt"
    reader = Reader(allowlist=[b"A3F29C11", b"B7E10422"], log_path=log_file)
    result = reader.present(Card(uid=b"DEADBEEF"))

    assert result is False
    uid, status = _parse_log(log_file)[0]
    assert uid == "DEADBEEF"
    assert status == "DENIED"


def test_uid_written_to_log(tmp_path):
    log_file = tmp_path / "observed_uids.txt"
    reader = Reader(allowlist=[b"A3F29C11"], log_path=log_file)

    reader.present(Card(uid=b"A3F29C11"))
    reader.present(Card(uid=b"DEADBEEF"))

    entries = _parse_log(log_file)
    assert [uid for uid, _ in entries] == ["A3F29C11", "DEADBEEF"]


def test_cloned_uid_grants_access(tmp_path):
    # Attacker observes a legitimate transaction and reads the log.
    log_file = tmp_path / "observed_uids.txt"
    reader = Reader(allowlist=[b"A3F29C11"], log_path=log_file)
    reader.present(Card(uid=b"A3F29C11"))

    captured_uid, _ = _parse_log(log_file)[0]
    cloned_card = Card(uid=captured_uid.encode())
    assert reader.present(cloned_card) is True
