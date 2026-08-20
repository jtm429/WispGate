from __future__ import annotations

import asyncio
import base64
import io
import json
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pytest

from appserve import Wisp, WispAsset, WispResponse
from appserve.client import AppserveClient, ServerInfo
from appserve.e2e import PeerSession, derive_session_keys, generate_identity, public_key_text


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


def paired_sessions(client: AppserveClient) -> PeerSession:
    master = bytes(range(32))
    session_id = "asset-session"
    android_to_wisp, wisp_to_android = derive_session_keys(master, session_id)
    created_at = time.monotonic()
    client._peer_sessions["android-user"] = PeerSession(
        session_id,
        client.client_id,
        "android-user",
        android_to_wisp,
        wisp_to_android,
        created_at=created_at,
    )
    return PeerSession(
        session_id,
        "android-user",
        client.client_id,
        android_to_wisp,
        wisp_to_android,
        created_at=created_at,
    )


def test_wisp_response_streams_asset_as_encrypted_bulk_data(tmp_path: Path) -> None:
    plaintext = bytes(range(256)) * 4096
    android_identity = generate_identity()
    wisp_identity = generate_identity()

    async def scenario() -> tuple[list[dict], dict, bytes]:
        observed_header: dict = {}
        observed_ciphertext = bytearray()

        async def bulk_server(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            observed_header.update(json.loads(await reader.readline()))
            writer.write(b'{"ok":true,"type":"bulk_ready"}\n')
            await writer.drain()
            remaining = observed_header["length"]
            while remaining:
                chunk = await reader.readexactly(min(64 * 1024, remaining))
                observed_ciphertext.extend(chunk)
                remaining -= len(chunk)
            writer.write(b'{"ok":true,"type":"bulk_complete"}\n')
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(bulk_server, "127.0.0.1", 0)
        bulk_port = server.sockets[0].getsockname()[1]
        client = AppserveClient(
            ServerInfo("127.0.0.1", 1, 2, b"unused", bulk_port=bulk_port),
            "asset-wisp",
            identity_key=wisp_identity,
        )
        client._session_token = "wisp-session-token"
        client._peer_keys["android-user"] = public_key_text(android_identity)
        writer = RecordingWriter()
        client._writer = writer  # type: ignore[assignment]
        android_session = paired_sessions(client)
        client.register(
            Wisp(
                "asset",
                "Asset",
                "",
                state=lambda: WispResponse(
                    html='<img src="https://wisp.local/_wispgate/assets/qr-code">',
                    assets=(WispAsset.from_bytes("qr-code", "qr.png", "image/png", plaintext),),
                ),
                action=lambda _: {"html": "unused"},
            )
        )

        await client._dispatch_session_body(
            "android-user",
            {"wisp_id": "asset", "action": "state_request"},
        )
        server.close()
        await server.wait_closed()

        now = time.monotonic()
        begin = android_session.decrypt(writer.messages[0], now=now)
        complete = android_session.decrypt(writer.messages[1], now=now)
        return [begin, complete], observed_header, bytes(observed_ciphertext)

    messages, header, ciphertext = asyncio.run(scenario())
    begin, complete = messages
    offer = begin["assets"]["files"][0]
    bulk = offer["bulk"]
    wrapped_key = base64.urlsafe_b64decode(bulk["encrypted_key"] + "=" * (-len(bulk["encrypted_key"]) % 4))
    nonce = base64.urlsafe_b64decode(bulk["nonce"] + "=" * (-len(bulk["nonce"]) % 4))
    content_key = android_identity.decrypt(
        wrapped_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA256(), label=None),
    )
    aad = b"\0".join(
        [
            b"wispgate-bulk-v1",
            b"asset-wisp",
            b"android-user",
            begin["assets"]["transfer_id"].encode(),
            b"qr-code",
            bulk["ticket"].encode(),
            str(len(plaintext)).encode(),
        ]
    )

    assert begin["response"]["html"] == '<img src="https://wisp.local/_wispgate/assets/qr-code">'
    assert offer["name"] == "qr.png"
    assert offer["content_type"] == "image/png"
    assert offer["size"] == len(plaintext)
    assert bulk["algorithm"] == "RSA-OAEP-256+A256GCM"
    assert header == {
        "type": "bulk",
        "session_token": "wisp-session-token",
        "ticket": bulk["ticket"],
        "role": "sender",
        "peer": "android-user",
        "length": len(plaintext) + 16,
    }
    assert AESGCM(content_key).decrypt(nonce, ciphertext, aad) == plaintext
    assert complete == {
        "wisp_id": "asset",
        "assets": {"type": "complete", "transfer_id": begin["assets"]["transfer_id"]},
    }


@pytest.mark.parametrize("asset_id", ["../qr", "..", "qr%2Fcode"])
def test_wisp_response_rejects_asset_ids_that_are_not_safe_url_segments(asset_id: str) -> None:
    client = AppserveClient(
        ServerInfo("127.0.0.1", 1, 2, b"unused", bulk_port=3),
        "asset-wisp",
        identity_key=generate_identity(),
    )
    client._peer_keys["android-user"] = public_key_text(generate_identity())

    with pytest.raises(ValueError, match="invalid Wisp response asset"):
        client._prepare_outbound_assets(
            "android-user",
            (WispAsset.from_bytes(asset_id, "qr.png", "image/png", b"png"),),
        )


@pytest.mark.parametrize("size", [True, 1.5, "3"])
def test_wisp_response_rejects_non_integer_asset_sizes(size: object) -> None:
    client = AppserveClient(
        ServerInfo("127.0.0.1", 1, 2, b"unused", bulk_port=3),
        "asset-wisp",
        identity_key=generate_identity(),
    )
    client._peer_keys["android-user"] = public_key_text(generate_identity())
    asset = WispAsset(
        "asset", "asset.bin", "application/octet-stream", size,
        lambda: io.BytesIO(b"x"),  # type: ignore[arg-type]
    )

    with pytest.raises(ValueError, match="invalid Wisp response asset"):
        client._prepare_outbound_assets("android-user", (asset,))
