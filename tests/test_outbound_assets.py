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
    # Tests inject an already-connected relay writer directly.
    client._relay_ready.set()
    return PeerSession(
        session_id,
        "android-user",
        client.client_id,
        android_to_wisp,
        wisp_to_android,
        created_at=created_at,
    )


@pytest.mark.parametrize("asset_id", ["../qr", "..", "qr%2Fcode"])
def test_wisp_response_rejects_asset_ids_that_are_not_safe_url_segments(asset_id: str) -> None:
    client = AppserveClient(
        ServerInfo("127.0.0.1", 1, 2, b"unused", "0" * 64, bulk_port=3),
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
        ServerInfo("127.0.0.1", 1, 2, b"unused", "0" * 64, bulk_port=3),
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
