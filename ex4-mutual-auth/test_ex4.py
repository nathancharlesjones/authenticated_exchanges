import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from derive_key import derive_key
from reader import Reader
from card import Card
from session import Session
from rogue_reader import RogueReader


MASTER = b"workshop_master_key"
UID    = b"A3F29C11"

# Reader key pair: private key stays on the reader hardware;
# public key is embedded in every card's firmware at provisioning time.
_READER_PRIVATE_KEY = Ed25519PrivateKey.generate()
_READER_PUBLIC_KEY  = _READER_PRIVATE_KEY.public_key()


def _make_reader():
    return Reader(master_key=MASTER, reader_private_key=_READER_PRIVATE_KEY)


def _make_card():
    return Card(uid=UID, card_key=derive_key(MASTER, UID), reader_public_key=_READER_PUBLIC_KEY)


def _parse_log(log_file):
    return dict(line.split("=", 1) for line in log_file.read_text().splitlines())


# --- Red exercise ---

def test_legitimate_session_grants_access(tmp_path):
    log_file = tmp_path / "last_session.txt"
    granted, card_accepted = Session(_make_reader(), _make_card(), log_path=log_file).run()

    assert granted is True
    assert card_accepted is True
    fields = _parse_log(log_file)
    assert fields["phase1_verified"] == "True"
    assert fields["card_accepted"] == "True"
    assert fields["result"] == "GRANTED"


def test_rogue_reader_card_rejects(tmp_path):
    log_file = tmp_path / "last_session.txt"
    granted, card_accepted = Session(RogueReader(), _make_card(), log_path=log_file).run()

    assert granted is False
    assert card_accepted is False
    assert _parse_log(log_file)["result"] == "DENIED"


def test_phase1_response_captured_before_rejection(tmp_path):
    # The card completes Phase 1 before it can detect the rogue reader in Phase 2.
    # The rogue reader has the card's Phase 1 response before being caught.
    log_file = tmp_path / "last_session.txt"
    Session(RogueReader(), _make_card(), log_path=log_file).run()

    fields = _parse_log(log_file)
    assert fields["phase1_verified"] == "True"
    assert "response_c" in fields
    assert fields["card_accepted"] == "False"
    assert fields["result"] == "DENIED"


def test_wrong_card_key_fails_phase1(tmp_path):
    wrong_card = Card(uid=UID, card_key=b"not_the_right_key",
                      reader_public_key=_READER_PUBLIC_KEY)
    granted, card_accepted = Session(_make_reader(), wrong_card,
                                      log_path=tmp_path / "last_session.txt").run()

    assert granted is False
    assert card_accepted is None  # Phase 2 never ran


def test_wrong_reader_private_key_fails_phase2(tmp_path):
    # A reader with a different private key cannot produce a signature that the
    # card's embedded public key will accept — even if Phase 1 succeeds.
    imposter = Reader(master_key=MASTER,
                      reader_private_key=Ed25519PrivateKey.generate())
    granted, card_accepted = Session(imposter, _make_card(),
                                      log_path=tmp_path / "last_session.txt").run()

    assert granted is False
    assert card_accepted is False


# --- Yellow exercise ---

def test_relay_attack_succeeds_despite_mutual_auth(tmp_path):
    # A transparent relay forwards all messages between a legitimate reader and card.
    # Both phases succeed through the relay — mutual auth proves keys, not proximity.
    legitimate_reader = _make_reader()

    class RelayMiddleman:
        def phase1_challenge(self):
            return legitimate_reader.phase1_challenge()
        def phase1_verify(self, uid, nonce_r, response_c):
            return legitimate_reader.phase1_verify(uid, nonce_r, response_c)
        def phase2_respond(self, nonce_c):
            return legitimate_reader.phase2_respond(nonce_c)

    granted, card_accepted = Session(RelayMiddleman(), _make_card(),
                                      log_path=tmp_path / "last_session.txt").run()
    assert granted is True
    assert card_accepted is True


# --- Green exercise ---
# To enable: remove the pytestmark line from TestGreenExercise.

class TestGreenExercise:
    pytestmark = pytest.mark.skip(reason="Green exercise: fill in phase2_challenge() and phase2_verify() in card_skeleton.py first")

    def test_skeleton_full_handshake_granted(self, tmp_path):
        from card_skeleton import Card as SkeletonCard
        card = SkeletonCard(uid=UID, card_key=derive_key(MASTER, UID),
                            reader_public_key=_READER_PUBLIC_KEY)
        granted, card_accepted = Session(_make_reader(), card,
                                          log_path=tmp_path / "last_session.txt").run()
        assert granted is True
        assert card_accepted is True

    def test_skeleton_rejects_rogue_reader(self, tmp_path):
        from card_skeleton import Card as SkeletonCard
        card = SkeletonCard(uid=UID, card_key=derive_key(MASTER, UID),
                            reader_public_key=_READER_PUBLIC_KEY)
        granted, card_accepted = Session(RogueReader(), card,
                                          log_path=tmp_path / "last_session.txt").run()
        assert granted is False
        assert card_accepted is False
