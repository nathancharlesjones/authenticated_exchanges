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


# --- Red exercise ---

def test_legitimate_session_grants_access(capsys):
    granted, card_accepted = Session(_make_reader(), _make_card()).run()

    assert granted is True
    assert card_accepted is True
    out = capsys.readouterr().out
    assert "[READER] Phase 1: Authenticating card..." in out
    assert "[READER] Card response verified. ✓" in out
    assert "[READER] Phase 2: Authenticating reader to card..." in out
    assert "[CARD]   Reader signature verified. ✓" in out
    assert "ACCESS GRANTED" in out


def test_rogue_reader_card_rejects(capsys):
    granted, card_accepted = Session(RogueReader(), _make_card()).run()

    assert granted is False
    assert card_accepted is False
    assert "ACCESS DENIED" in capsys.readouterr().out


def test_phase1_response_captured_before_rejection(capsys):
    # The card completes Phase 1 before it can detect the rogue reader in Phase 2.
    # The rogue reader has the card's Phase 1 response before being caught.
    Session(RogueReader(), _make_card()).run()

    out = capsys.readouterr().out
    assert "[CARD]   Sending response:" in out
    assert "[ROGUE]  Phase 1 response captured:" in out
    assert "[CARD]   Reader signature invalid. Rejecting." in out


def test_wrong_card_key_fails_phase1():
    wrong_card = Card(uid=UID, card_key=b"not_the_right_key",
                      reader_public_key=_READER_PUBLIC_KEY)
    granted, card_accepted = Session(_make_reader(), wrong_card).run()

    assert granted is False
    assert card_accepted is None  # Phase 2 never ran


def test_wrong_reader_private_key_fails_phase2():
    # A reader with a different private key cannot produce a signature that the
    # card's embedded public key will accept — even if Phase 1 succeeds.
    imposter = Reader(master_key=MASTER,
                      reader_private_key=Ed25519PrivateKey.generate())
    granted, card_accepted = Session(imposter, _make_card()).run()

    assert granted is False
    assert card_accepted is False


# --- Yellow exercise ---

def test_relay_attack_succeeds_despite_mutual_auth():
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

    granted, card_accepted = Session(RelayMiddleman(), _make_card()).run()
    assert granted is True
    assert card_accepted is True


# --- Green exercise ---
# To enable: remove the pytestmark line from TestGreenExercise.

class TestGreenExercise:
    pytestmark = pytest.mark.skip(reason="Green exercise: fill in phase2_challenge() and phase2_verify() in card_skeleton.py first")

    def test_skeleton_full_handshake_granted(self):
        from card_skeleton import Card as SkeletonCard
        card = SkeletonCard(uid=UID, card_key=derive_key(MASTER, UID),
                            reader_public_key=_READER_PUBLIC_KEY)
        granted, card_accepted = Session(_make_reader(), card).run()
        assert granted is True
        assert card_accepted is True

    def test_skeleton_rejects_rogue_reader(self):
        from card_skeleton import Card as SkeletonCard
        card = SkeletonCard(uid=UID, card_key=derive_key(MASTER, UID),
                            reader_public_key=_READER_PUBLIC_KEY)
        granted, card_accepted = Session(RogueReader(), card).run()
        assert granted is False
        assert card_accepted is False
