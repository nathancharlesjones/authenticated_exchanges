import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from derive_key import derive_key
from reader import Reader
from badge import Badge
from session import Session
from rogue_reader import RogueReader
from channel import Channel


FLEET = os.urandom(16)
UID    = b"A3F29C11"

# Reader key pair: private key stays on the reader hardware;
# public key is embedded in every badge's firmware at provisioning time.
_READER_PRIVATE_KEY = Ed25519PrivateKey.generate()
_READER_PUBLIC_KEY  = _READER_PRIVATE_KEY.public_key()


def _make_reader():
    return Reader(fleet_key=FLEET, reader_private_key=_READER_PRIVATE_KEY)


def _make_badge():
    return Badge(uid=UID, badge_key=derive_key(FLEET, UID), reader_public_key=_READER_PUBLIC_KEY)


def _parse_log(log_file):
    return dict(line.split("=", 1) for line in log_file.read_text().splitlines())


# --- Red exercise ---

def test_legitimate_session_grants_access(log_path):
    channel = Session(_make_reader(), _make_badge(), log_path=log_path).run()

    assert isinstance(channel, Channel)
    fields = _parse_log(log_path)
    assert fields["phase1_verified"] == "True"
    assert fields["badge_accepted"] == "True"
    assert fields["result"] == "GRANTED"


def test_channel_command_roundtrip(log_path):
    channel = Session(_make_reader(), _make_badge(), log_path=log_path).run()
    assert "DEADBEEF" in channel.send_command("READ_SECTOR 1")


def test_handle_command_requires_authenticated_session():
    with pytest.raises(PermissionError):
        _make_badge().handle_command("READ_SECTOR 0")


def test_rogue_reader_badge_rejects(log_path):
    channel = Session(RogueReader(), _make_badge(), log_path=log_path).run()

    assert channel is None
    assert _parse_log(log_path)["result"] == "DENIED"


def test_phase1_response_captured_before_rejection(log_path):
    # The badge completes Phase 1 before it can detect the rogue reader in Phase 2.
    # The rogue reader has the badge's Phase 1 response before being caught.
    Session(RogueReader(), _make_badge(), log_path=log_path).run()

    fields = _parse_log(log_path)
    assert fields["phase1_verified"] == "True"
    assert "response_c" in fields
    assert fields["badge_accepted"] == "False"
    assert fields["result"] == "DENIED"


def test_wrong_badge_key_fails_phase1(log_path):
    wrong_badge = Badge(uid=UID, badge_key=b"not_the_right_key",
                      reader_public_key=_READER_PUBLIC_KEY)
    channel = Session(_make_reader(), wrong_badge, log_path=log_path).run()

    assert channel is None
    assert "badge_accepted" not in _parse_log(log_path)  # Phase 2 never ran


def test_wrong_reader_private_key_fails_phase2(log_path):
    # A reader with a different private key cannot produce a signature that the
    # badge's embedded public key will accept — even if Phase 1 succeeds.
    imposter = Reader(fleet_key=FLEET,
                      reader_private_key=Ed25519PrivateKey.generate())
    channel = Session(imposter, _make_badge(), log_path=log_path).run()

    assert channel is None


# --- Yellow exercise ---

def test_relay_attack_succeeds_despite_mutual_auth(log_path):
    # A transparent relay forwards all messages between a legitimate reader and badge.
    # Both phases succeed through the relay — mutual auth proves keys, not proximity.
    legitimate_reader = _make_reader()

    class RelayMiddleman:
        def phase1_challenge(self):
            return legitimate_reader.phase1_challenge()
        def phase1_verify(self, uid, nonce_r, response_c):
            return legitimate_reader.phase1_verify(uid, nonce_r, response_c)
        def phase2_respond(self, nonce_c):
            return legitimate_reader.phase2_respond(nonce_c)

    channel = Session(RelayMiddleman(), _make_badge(), log_path=log_path).run()
    assert isinstance(channel, Channel)
