from __future__ import annotations

import base64
import copy

import pytest

from appserve.e2e import (
    SESSION_LIFETIME_SECONDS,
    PeerSession,
    derive_session_keys,
    session_aad,
    session_nonce,
)

MASTER = bytes(range(32))
SESSION_ID = "fixture-session"
ANDROID_KEY = "a8939e89e7802a5eb2d16ab1cca6a8e4e271b6f558e7edfb931a5a8633bb989d"
WISP_KEY = "2d25b59f6cf17aeac50fe64d89fe94b1faf7aeb92589ce75f861f62b97ed6585"
CIPHERTEXT = "35795103fff46cace67a89b589f4c1bc5ed059b8f8887d13a2642a379a17ee4c96c45e2b1c253e530844"


def test_session_crypto_matches_cross_language_fixture() -> None:
    android_key, wisp_key = derive_session_keys(MASTER, SESSION_ID)
    assert android_key.hex() == ANDROID_KEY
    assert wisp_key.hex() == WISP_KEY
    assert session_nonce(7).hex() == "574701000000000000000007"
    assert session_aad(SESSION_ID, "android-user", "prime-wisp", 7).decode() == (
        '{"recipient":"prime-wisp","sender":"android-user","sequence":7,'
        '"session_id":"fixture-session","type":"session_envelope","version":1}'
    )
    sender = PeerSession(SESSION_ID, "android-user", "prime-wisp", android_key, wisp_key, created_at=100.0)
    envelope = sender.encrypt({"action": "state_request"}, now=101.0)
    assert base64.urlsafe_b64decode(envelope["ciphertext"] + "==").hex() == CIPHERTEXT
    receiver = PeerSession(SESSION_ID, "prime-wisp", "android-user", android_key, wisp_key, created_at=100.0)
    assert receiver.decrypt(envelope, now=101.0) == {"action": "state_request"}


def test_session_crypto_rejects_replay_tampering_and_absolute_expiration() -> None:
    android_key, wisp_key = derive_session_keys(MASTER, SESSION_ID)
    sender = PeerSession(SESSION_ID, "android-user", "prime-wisp", android_key, wisp_key, created_at=10.0)
    receiver = PeerSession(SESSION_ID, "prime-wisp", "android-user", android_key, wisp_key, created_at=10.0)
    envelope = sender.encrypt({"n": 1}, now=11.0)
    assert receiver.decrypt(envelope, now=11.0) == {"n": 1}
    with pytest.raises(ValueError, match="sequence"):
        receiver.decrypt(envelope, now=12.0)
    changed = copy.deepcopy(sender.encrypt({"n": 2}, now=12.0))
    changed["recipient"] = "attacker"
    with pytest.raises(ValueError, match="route"):
        receiver.decrypt(changed, now=12.0)
    with pytest.raises(ValueError, match="expired"):
        sender.encrypt({"n": 3}, now=10.0 + SESSION_LIFETIME_SECONDS)
    with pytest.raises(ValueError, match="sequence"):
        session_nonce(1 << 64)
