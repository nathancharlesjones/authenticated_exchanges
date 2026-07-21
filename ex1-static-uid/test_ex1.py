import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from reader import Reader
from badge import Badge


def _parse_log(log_file):
    return [line.split(",") for line in log_file.read_text().splitlines()]


def test_known_uid_grants_access(log_path):
    reader = Reader(allowlist=[b"A3F29C11", b"B7E10422"], log_path=log_path)
    result = reader.present(Badge(uid=b"A3F29C11"))

    assert result is True
    uid, status = _parse_log(log_path)[0]
    assert uid == "A3F29C11"
    assert status == "GRANTED"


def test_unknown_uid_denies_access(log_path):
    reader = Reader(allowlist=[b"A3F29C11", b"B7E10422"], log_path=log_path)
    result = reader.present(Badge(uid=b"DEADBEEF"))

    assert result is False
    uid, status = _parse_log(log_path)[0]
    assert uid == "DEADBEEF"
    assert status == "DENIED"


def test_uid_written_to_log(log_path):
    reader = Reader(allowlist=[b"A3F29C11"], log_path=log_path)

    reader.present(Badge(uid=b"A3F29C11"))
    reader.present(Badge(uid=b"DEADBEEF"))

    entries = _parse_log(log_path)
    assert [uid for uid, _ in entries] == ["A3F29C11", "DEADBEEF"]
