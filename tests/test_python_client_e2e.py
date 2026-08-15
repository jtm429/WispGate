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

    def close(self) -> None:
        pass

    async def wait_closed(self) -> None:
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
        request = encrypt_envelope(
            sender="android-user",
            recipient="upload-wisp",
            message_id="request-1",
            body={
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
            recipient_public_key=public_key_text(wisp_identity),
            sender_private_key=android,
            advertise_sender_key=True,
        )
        await client._handle_envelope(request)
        ready, _ = decrypt_envelope(writer.messages[0], android, public_key_text(wisp_identity))
        assert ready["transfer"] == {"type": "ready", "transfer_id": "transfer-1"}
        for _ in range(100):
            if len(writer.messages) == 2:
                break
            await asyncio.sleep(0.01)
        if len(writer.messages) != 2:
            transfer = client._transfers.get(("android-user", "transfer-1"))
            task = transfer.task if transfer else None
            detail = task.exception() if task and task.done() and not task.cancelled() else None
            raise AssertionError(f"bulk completion missing; header={received_header!r} task={detail!r}")
        complete, _ = decrypt_envelope(writer.messages[1], android, public_key_text(wisp_identity))
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
