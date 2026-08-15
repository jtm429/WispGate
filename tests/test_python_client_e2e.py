from __future__ import annotations

import asyncio
import base64
import json
from pathlib import Path

from appserve.client import AppserveClient, ServerInfo, Wisp, WispAction
from appserve.e2e import decrypt_envelope, encrypt_envelope, generate_identity, public_key_text
from server.appserve_server.core import RelayConfig, generate_server_keypair


class RecordingWriter:
    def __init__(self) -> None:
        self.messages: list[dict] = []

    def write(self, data: bytes) -> None:
        self.messages.append(json.loads(data))

    async def drain(self) -> None:
        pass


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
    request = encrypt_envelope(
        sender="android-user",
        recipient="prime-wisp",
        message_id="request-1",
        body={"wisp_id": "prime", "action": "state_request"},
        recipient_public_key=public_key_text(wisp_identity),
        sender_private_key=android,
        advertise_sender_key=True,
    )

    asyncio.run(client._handle_envelope(request))

    assert client.peer_public_key("android-user") == public_key_text(android)
    assert len(writer.messages) == 1
    response = writer.messages[0]
    assert "body" not in response
    assert "secret state" not in str(response)
    body, _ = decrypt_envelope(response, android, public_key_text(wisp_identity))
    assert body == {"wisp_id": "prime", "response": {"html": "<p>secret state</p>"}}


def test_encrypted_file_manifest_chunks_and_commit_invoke_generic_wisp_action(tmp_path: Path) -> None:
    android = generate_identity()
    wisp_identity = generate_identity()
    info, _ = make_info(tmp_path)
    observed: dict[str, object] = {}

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

    client = AppserveClient(info, "upload-wisp", identity_key=wisp_identity, transfer_directory=tmp_path / "uploads")
    client.register(Wisp("upload", "Upload", "", state=lambda: {"html": ""}, action=handle))
    writer = RecordingWriter()
    client._writer = writer  # type: ignore[assignment]

    async def send(body: dict) -> dict:
        request = encrypt_envelope(
            sender="android-user",
            recipient="upload-wisp",
            message_id=f"request-{len(writer.messages)}",
            body=body,
            recipient_public_key=public_key_text(wisp_identity),
            sender_private_key=android,
            advertise_sender_key=not writer.messages,
        )
        await client._handle_envelope(request)
        response, _ = decrypt_envelope(writer.messages[-1], android, public_key_text(wisp_identity))
        return response

    async def scenario() -> tuple[dict, dict, dict]:
        ready = await send({
            "wisp_id": "upload",
            "action": "file_begin",
            "transfer_id": "transfer-1",
            "action_data": {"type": "transcribe", "language": "en"},
            "files": [{
                "id": "file-1",
                "field": "recording",
                "name": "voice.ogg",
                "content_type": "audio/ogg",
                "size": 11,
            }],
        })
        chunk = await send({
            "wisp_id": "upload",
            "action": "file_chunk",
            "transfer_id": "transfer-1",
            "file_id": "file-1",
            "offset": 0,
            "data": base64.urlsafe_b64encode(b"hello world").decode().rstrip("="),
        })
        complete = await send({
            "wisp_id": "upload",
            "action": "file_commit",
            "transfer_id": "transfer-1",
        })
        return ready, chunk, complete

    ready, chunk, complete = asyncio.run(scenario())

    assert ready["transfer"] == {
        "type": "ready",
        "transfer_id": "transfer-1",
        "chunk_size": AppserveClient.FILE_CHUNK_BYTES,
    }
    assert chunk["transfer"] == {
        "type": "chunk_accepted",
        "transfer_id": "transfer-1",
        "file_id": "file-1",
        "next_offset": 11,
    }
    assert complete == {"wisp_id": "upload", "response": {"html": "<p>received</p>"}}
    assert observed == {
        "action": {"type": "transcribe", "language": "en"},
        "name": "voice.ogg",
        "content_type": "audio/ogg",
        "size": 11,
        "bytes": b"hello world",
    }
    assert not list((tmp_path / "uploads").glob("**/*.upload"))
    assert "voice.ogg" not in str(writer.messages)
    assert "hello world" not in str(writer.messages)


def test_file_commit_rejects_incomplete_transfer_without_calling_wisp(tmp_path: Path) -> None:
    android = generate_identity()
    wisp_identity = generate_identity()
    info, _ = make_info(tmp_path)
    calls: list[WispAction] = []
    client = AppserveClient(info, "upload-wisp", identity_key=wisp_identity, transfer_directory=tmp_path / "uploads")
    client.register(Wisp("upload", "Upload", "", state=lambda: {"html": ""}, action=lambda action: calls.append(action) or {"html": "bad"}))
    writer = RecordingWriter()
    client._writer = writer  # type: ignore[assignment]

    async def send(body: dict) -> dict:
        request = encrypt_envelope(
            sender="android-user",
            recipient="upload-wisp",
            message_id=f"request-{len(writer.messages)}",
            body=body,
            recipient_public_key=public_key_text(wisp_identity),
            sender_private_key=android,
            advertise_sender_key=not writer.messages,
        )
        await client._handle_envelope(request)
        response, _ = decrypt_envelope(writer.messages[-1], android, public_key_text(wisp_identity))
        return response

    async def scenario() -> dict:
        await send({
            "wisp_id": "upload",
            "action": "file_begin",
            "transfer_id": "short",
            "action_data": {"type": "upload"},
            "files": [{"id": "f", "field": "file", "name": "x.bin", "content_type": "application/octet-stream", "size": 5}],
        })
        return await send({"wisp_id": "upload", "action": "file_commit", "transfer_id": "short"})

    response = asyncio.run(scenario())

    assert response["transfer"]["type"] == "error"
    assert response["transfer"]["transfer_id"] == "short"
    assert "incomplete" in response["transfer"]["error"]
    assert calls == []
    assert not list((tmp_path / "uploads").glob("**/*.upload"))
