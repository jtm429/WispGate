from __future__ import annotations

import asyncio
import base64
import json
import logging
from pathlib import Path

from appserve.client import AppserveClient, ServerInfo, Wisp, WispAction
from appserve.e2e import (
    PeerSession,
    derive_session_keys,
    encrypt_envelope,
    generate_identity,
    public_key_text,
)
from server.appserve_server.core import RelayConfig, generate_server_keypair


class RecordingWriter:
    def __init__(self) -> None:
        self.messages: list[dict] = []

    def write(self, data: bytes) -> None:
        self.messages.append(json.loads(data))

    async def drain(self) -> None:
        pass

    def close(self) -> None:
        pass

    async def wait_closed(self) -> None:
        pass


async def establish_peer_session(client: AppserveClient, android_identity, wisp_identity) -> PeerSession:
    master = bytes(range(32))
    session_id = "test-session"
    request = encrypt_envelope(
        sender="android-user",
        recipient=client.client_id,
        message_id="session-init",
        body={
            "type": "session_init",
            "session_id": session_id,
            "challenge": "test-challenge",
            "master_secret": base64.urlsafe_b64encode(master).decode().rstrip("="),
        },
        recipient_public_key=public_key_text(wisp_identity),
        sender_private_key=android_identity,
        advertise_sender_key=True,
    )
    await client._handle_envelope(request)
    android_to_wisp, wisp_to_android = derive_session_keys(master, session_id)
    return PeerSession(
        session_id,
        "android-user",
        client.client_id,
        android_to_wisp,
        wisp_to_android,
        created_at=client._peer_sessions["android-user"].created_at,
    )


def test_public_package_exports_reusable_file_action_types() -> None:
    from appserve import UploadedFile as PublicUploadedFile
    from appserve import WispAction as PublicWispAction

    assert PublicUploadedFile.__name__ == "UploadedFile"
    assert PublicWispAction.__name__ == "WispAction"


def make_info(tmp_path: Path) -> tuple[ServerInfo, RelayConfig]:
    server_key_path = tmp_path / "server.pem"
    public = generate_server_keypair(server_key_path)
    config = RelayConfig(server_key_path.read_bytes())
    import base64

    return ServerInfo("localhost", 1, 2, base64.urlsafe_b64decode(public)), config


def test_python_wisp_registration_supplies_real_endpoint_public_key(tmp_path: Path) -> None:
    identity = generate_identity()
    info, _ = make_info(tmp_path)
    client = AppserveClient(info, "prime-wisp", identity_key=identity)

    registration = client._registration_message()

    assert registration["client_public_key"] == public_key_text(identity)


def test_event_loop_accepts_legacy_success_ack_without_unknown_type_warning(tmp_path: Path, caplog) -> None:
    identity = generate_identity()
    info, _ = make_info(tmp_path)
    client = AppserveClient(info, "prime-wisp", identity_key=identity)
    async def scenario() -> None:
        reader = asyncio.StreamReader()
        reader.feed_data(b'{"ok":true}\n')
        reader.feed_eof()
        client._reader = reader
        await client._event_loop()

    with caplog.at_level(logging.WARNING, logger="appserve.client"):
        asyncio.run(scenario())

    assert "discarding unknown relay message type" not in caplog.text


def test_unknown_peer_session_requests_reset(tmp_path: Path) -> None:
    identity = generate_identity()
    info, _ = make_info(tmp_path)
    client = AppserveClient(info, "prime-wisp", identity_key=identity)
    writer = RecordingWriter()
    client._writer = writer  # type: ignore[assignment]
    stale = {
        "version": 1,
        "type": "session_envelope",
        "session_id": "stale-session",
        "sender": "android-user",
        "recipient": "prime-wisp",
        "sequence": 0,
        "ciphertext": "ignored-before-decryption",
    }

    async def scenario() -> None:
        try:
            await client._handle_session_envelope(stale)
        except ValueError as cause:
            assert str(cause) == "unknown session"

    asyncio.run(scenario())

    assert writer.messages == [{
        "type": "session_reset",
        "sender": "prime-wisp",
        "recipient": "android-user",
        "reason": "unknown_session",
    }]


def test_python_wisp_decrypts_first_refresh_and_encrypts_response(tmp_path: Path) -> None:
    android = generate_identity()
    wisp_identity = generate_identity()
    info, _ = make_info(tmp_path)
    client = AppserveClient(info, "prime-wisp", identity_key=wisp_identity)
    client.register(
        Wisp(
            "prime",
            "Prime tester",
            "",
            state=lambda: {"html": "<p>secret state</p>"},
            action=lambda _: {"html": "unused"},
        )
    )
    writer = RecordingWriter()
    client._writer = writer  # type: ignore[assignment]
    async def scenario() -> dict:
        session = await establish_peer_session(client, android, wisp_identity)
        request = session.encrypt(
            {"wisp_id": "prime", "action": "state_request"},
            now=client._peer_sessions["android-user"].created_at + 1,
        )
        await client._handle_session_envelope(request)
        return session.decrypt(
            writer.messages[1],
            now=client._peer_sessions["android-user"].created_at + 1,
        )

    body = asyncio.run(scenario())

    assert client.peer_public_key("android-user") == public_key_text(android)
    assert len(writer.messages) == 2
    response = writer.messages[1]
    assert response["type"] == "session_envelope"
    assert "body" not in response
    assert "secret state" not in str(response)
    assert "encrypted_key" not in response
    assert "signature" not in response
    assert body == {"wisp_id": "prime", "response": {"html": "<p>secret state</p>"}}


def test_encrypted_bulk_file_invokes_generic_wisp_action(tmp_path: Path) -> None:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    android = generate_identity()
    wisp_identity = generate_identity()
    observed: dict[str, object] = {}
    plaintext = b"hello world"
    ticket = "bulk-ticket-1234567890"
    file_key = AESGCM.generate_key(bit_length=256)
    nonce = b"0123456789ab"
    aad = b"\0".join([
        b"wispgate-bulk-v1", b"android-user", b"upload-wisp", b"transfer-1", b"file-1", ticket.encode(), b"11",
    ])
    ciphertext = AESGCM(file_key).encrypt(nonce, plaintext, aad)
    wrapped_key = wisp_identity.public_key().encrypt(
        file_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA256(), label=None),
    )

    def handle(action: WispAction) -> dict[str, str]:
        upload = action.files["recording"]
        observed.update(
            action=dict(action),
            name=upload.name,
            content_type=upload.content_type,
            size=upload.size,
            bytes=upload.read_bytes(),
        )
        return {"html": "<p>received</p>"}

    async def scenario() -> tuple[dict, dict]:
        received_header: dict = {}

        async def bulk_server(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            received_header.update(json.loads(await reader.readline()))
            writer.write(b'{"ok":true,"type":"bulk_ready"}\n' + ciphertext)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(bulk_server, "127.0.0.1", 0)
        bulk_port = server.sockets[0].getsockname()[1]
        info, _ = make_info(tmp_path)
        info = ServerInfo("127.0.0.1", info.control_port, info.relay_port, info.server_public_key, bulk_port=bulk_port)
        client = AppserveClient(info, "upload-wisp", identity_key=wisp_identity, transfer_directory=tmp_path / "uploads")
        client._session_token = "wisp-session"
        client.register(Wisp("upload", "Upload", "", state=lambda: {"html": ""}, action=handle))
        writer = RecordingWriter()
        client._writer = writer  # type: ignore[assignment]
        android_session = await establish_peer_session(client, android, wisp_identity)
        request = android_session.encrypt(
            {
                "wisp_id": "upload",
                "action": "file_begin",
                "transfer_id": "transfer-1",
                "action_data": {"type": "transcribe", "language": "en"},
                "files": [{
                    "id": "file-1",
                    "field": "recording",
                    "name": "voice.ogg",
                    "content_type": "audio/ogg",
                    "size": len(plaintext),
                    "bulk": {
                        "algorithm": "RSA-OAEP-256+A256GCM",
                        "ticket": ticket,
                        "encrypted_key": base64.urlsafe_b64encode(wrapped_key).decode().rstrip("="),
                        "nonce": base64.urlsafe_b64encode(nonce).decode().rstrip("="),
                        "ciphertext_size": len(ciphertext),
                    },
                }],
            },
            now=client._peer_sessions["android-user"].created_at + 1,
        )
        await client._handle_session_envelope(request)
        ready = android_session.decrypt(
            writer.messages[1], now=client._peer_sessions["android-user"].created_at + 1,
        )

        assert ready["transfer"] == {"type": "ready", "transfer_id": "transfer-1"}
        for _ in range(100):
            if len(writer.messages) == 3:
                break
            await asyncio.sleep(0.01)
        if len(writer.messages) != 3:
            transfer = client._transfers.get(("android-user", "transfer-1"))
            task = transfer.task if transfer else None
            detail = task.exception() if task and task.done() and not task.cancelled() else None
            raise AssertionError(f"bulk completion missing; header={received_header!r} task={detail!r}")
        complete = android_session.decrypt(
            writer.messages[2], now=client._peer_sessions["android-user"].created_at + 1,
        )
        await client.close()
        server.close()
        await server.wait_closed()
        return ready, complete, received_header

    ready, complete, received_header = asyncio.run(scenario())

    assert ready["transfer"] == {"type": "ready", "transfer_id": "transfer-1"}
    assert complete == {"wisp_id": "upload", "response": {"html": "<p>received</p>"}}
    assert received_header == {
        "type": "bulk",
        "session_token": "wisp-session",
        "ticket": ticket,
        "role": "receiver",
        "peer": "android-user",
        "length": len(ciphertext),
    }
    assert observed == {
        "action": {"type": "transcribe", "language": "en"},
        "name": "voice.ogg",
        "content_type": "audio/ogg",
        "size": len(plaintext),
        "bytes": plaintext,
    }
    assert not list((tmp_path / "uploads").glob("**/*.upload"))
