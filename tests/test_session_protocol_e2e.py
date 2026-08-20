from __future__ import annotations

import asyncio
import base64
import json

import pytest

from appserve.client import AppserveClient, ServerInfo, Wisp
from appserve.e2e import (
    PeerSession,
    decrypt_envelope,
    derive_session_keys,
    encrypt_envelope,
    generate_identity,
    public_key_text,
    session_accept_proof,
)


class RecordingWriter:
    def __init__(self) -> None:
        self.messages: list[dict] = []

    def write(self, data: bytes) -> None:
        import json
        self.messages.append(json.loads(data))

    async def drain(self) -> None: pass
    def close(self) -> None: pass
    async def wait_closed(self) -> None: pass


def test_authenticated_handshake_then_symmetric_actions_and_cleanup() -> None:
    android = generate_identity()
    wisp_key = generate_identity()
    client = AppserveClient(ServerInfo("localhost", 1, 2, b"unused"), "prime-wisp", identity_key=wisp_key)
    client.register(Wisp("prime", "Prime", "", state=lambda: {"html": "state"}, action=lambda action: {"html": action["value"]}))
    writer = RecordingWriter()
    client._writer = writer  # type: ignore[assignment]
    master = bytes(range(32))
    session_id = "session-1"
    challenge = "challenge-1"
    init = encrypt_envelope(
        sender="android-user", recipient="prime-wisp", message_id="handshake-1",
        body={"type": "session_init", "session_id": session_id,
              "master_secret": base64.urlsafe_b64encode(master).decode().rstrip("="), "challenge": challenge},
        recipient_public_key=public_key_text(wisp_key), sender_private_key=android, advertise_sender_key=True,
    )

    asyncio.run(client._handle_envelope(init))

    assert client.peer_public_key("android-user") == public_key_text(android)
    accept, _ = decrypt_envelope(writer.messages[0], android, public_key_text(wisp_key))
    assert accept == {
        "type": "session_accept", "session_id": session_id, "challenge": challenge,
        "proof": session_accept_proof(master, session_id, challenge, "android-user", "prime-wisp"),
    }
    android_to_wisp, wisp_to_android = derive_session_keys(master, session_id)
    android_session = PeerSession(session_id, "android-user", "prime-wisp", android_to_wisp, wisp_to_android, created_at=client._peer_sessions["android-user"].created_at)
    request = android_session.encrypt({"wisp_id": "prime", "action": "state_request"}, now=client._peer_sessions["android-user"].created_at + 1)
    asyncio.run(client._handle_session_envelope(request))
    response = writer.messages[1]
    assert response["type"] == "session_envelope"
    assert "encrypted_key" not in response and "signature" not in response
    assert android_session.decrypt(response, now=client._peer_sessions["android-user"].created_at + 1) == {
        "wisp_id": "prime", "response": {"html": "state"}
    }

    with pytest.raises(ValueError, match="sequence"):
        asyncio.run(client._handle_session_envelope(request))
    assert "android-user" not in client._peer_sessions
    asyncio.run(client.close())
    assert client._peer_sessions == {}


def test_rsa_application_message_is_not_a_compatibility_path() -> None:
    android = generate_identity()
    wisp_key = generate_identity()
    client = AppserveClient(ServerInfo("localhost", 1, 2, b"unused"), "prime-wisp", identity_key=wisp_key)
    legacy = encrypt_envelope(
        sender="android-user", recipient="prime-wisp", message_id="old",
        body={"wisp_id": "prime", "action": "state_request"},
        recipient_public_key=public_key_text(wisp_key), sender_private_key=android, advertise_sender_key=True,
    )
    with pytest.raises(ValueError, match="session_init"):
        asyncio.run(client._handle_envelope(legacy))


def test_invalid_session_frame_does_not_drop_wisp_identity_connection() -> None:
    android = generate_identity()
    wisp_key = generate_identity()
    client = AppserveClient(ServerInfo("localhost", 1, 2, b"unused"), "prime-wisp", identity_key=wisp_key)
    writer = RecordingWriter()
    client._writer = writer  # type: ignore[assignment]
    invalid = {
        "version": 1, "type": "session_envelope", "session_id": "lost",
        "sender": "android-user", "recipient": "prime-wisp", "sequence": 0,
        "ciphertext": "unknown-session",
    }
    master = bytes(range(32))
    handshake = encrypt_envelope(
        sender="android-user", recipient="prime-wisp", message_id="handshake-after-loss",
        body={
            "type": "session_init", "session_id": "replacement", "challenge": "challenge",
            "master_secret": base64.urlsafe_b64encode(master).decode().rstrip("="),
        },
        recipient_public_key=public_key_text(wisp_key), sender_private_key=android,
        advertise_sender_key=True,
    )
    lines = iter((json.dumps(invalid).encode() + b"\n", json.dumps(handshake).encode() + b"\n", b""))

    class LineReader:
        async def readline(self) -> bytes:
            return next(lines)

    client._reader = LineReader()  # type: ignore[assignment]

    asyncio.run(client._event_loop())

    assert writer.messages[0] == {
        "type": "session_reset",
        "sender": "prime-wisp",
        "recipient": "android-user",
        "reason": "unknown_session",
    }
    assert len(writer.messages) == 2
    accepted, _ = decrypt_envelope(writer.messages[1], android, public_key_text(wisp_key))
    assert accepted["type"] == "session_accept"
    assert accepted["session_id"] == "replacement"
