from __future__ import annotations

import asyncio
import json
from pathlib import Path

from appserve.client import AppserveClient, ServerInfo, Wisp
from appserve.e2e import decrypt_envelope, encrypt_envelope, generate_identity, public_key_text
from server.appserve_server.core import RelayConfig, generate_server_keypair


class RecordingWriter:
    def __init__(self) -> None:
        self.messages: list[dict] = []

    def write(self, data: bytes) -> None:
        self.messages.append(json.loads(data))

    async def drain(self) -> None:
        pass


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
