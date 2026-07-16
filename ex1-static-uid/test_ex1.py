import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from reader import Reader
from card import Card


def test_known_uid_grants_access(capsys, tmp_path):
    reader = Reader(allowlist=[b"A3F29C11", b"B7E10422"], log_path=tmp_path / "observed_uids.txt")
    card = Card(uid=b"A3F29C11")
    result = reader.present(card)

    assert result is True
    out = capsys.readouterr().out
    assert "[READER] Received UID: A3F29C11" in out
    assert "ACCESS GRANTED" in out


def test_unknown_uid_denies_access(capsys, tmp_path):
    reader = Reader(allowlist=[b"A3F29C11", b"B7E10422"], log_path=tmp_path / "observed_uids.txt")
    card = Card(uid=b"DEADBEEF")
    result = reader.present(card)

    assert result is False
    out = capsys.readouterr().out
    assert "[READER] Received UID: DEADBEEF" in out
    assert "ACCESS DENIED" in out


def test_uid_written_to_log(tmp_path):
    log_file = tmp_path / "observed_uids.txt"
    reader = Reader(allowlist=[b"A3F29C11"], log_path=log_file)

    reader.present(Card(uid=b"A3F29C11"))
    reader.present(Card(uid=b"DEADBEEF"))

    lines = log_file.read_text().splitlines()
    assert lines == ["A3F29C11", "DEADBEEF"]


def test_cloned_uid_grants_access(tmp_path):
    # Attacker observes a legitimate transaction and reads the log.
    log_file = tmp_path / "observed_uids.txt"
    reader = Reader(allowlist=[b"A3F29C11"], log_path=log_file)
    reader.present(Card(uid=b"A3F29C11"))

    captured_uid = log_file.read_text().splitlines()[0]
    cloned_card = Card(uid=captured_uid.encode())
    assert reader.present(cloned_card) is True
