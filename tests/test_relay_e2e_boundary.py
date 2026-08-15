from __future__ import annotations

import asyncio
import json
from pathlib import Path

from server.appserve_server.core import RelayConfig, RelayState
from server.appserve_server.service import RelayRuntime
from appserve.e2e import generate_identity, public_key_text


class RecordingWriter:
    def __init__(self) -> None:
        self.messages: list[dict] = []

    def write(self, data: bytes) -> None:
        self.messages.append(json.loads(data))

    async def drain(self) -> None:
        pass


def runtime(tmp_path: Path) -> RelayRuntime:
    return RelayRuntime(RelayConfig(b""), RelayState(tmp_path / "state.json"))


def test_catalog_distributes_wisp_owner_public_key(tmp_path: Path) -> None:
    relay = runtime(tmp_path)
    public_key = public_key_text(generate_identity())
    relay.state.clients["prime-wisp"] = {"public_key": public_key}
    relay.state.wisps["prime"] = {
        "id": "prime",
        "name": "Prime tester",
        "description": "",
        "owner": "prime-wisp",
    }

    assert relay.catalog_items() == [
        {
            "id": "prime",
            "name": "Prime tester",
            "description": "",
            "owner": "prime-wisp",
            "public_key": public_key,
        }
    ]


def test_catalog_omits_legacy_client_id_placeholder_key(tmp_path: Path) -> None:
    relay = runtime(tmp_path)
    relay.state.clients["prime-wisp"] = {"public_key": "prime-wisp"}
    relay.state.wisps["prime"] = {"id": "prime", "name": "Prime", "owner": "prime-wisp"}

    assert relay.catalog_items() == []


def test_bootstrap_placeholder_cannot_replace_registered_endpoint_key(tmp_path: Path) -> None:
    state = RelayState(tmp_path / "state.json")
    state.register_client("prime-wisp", "real-public-key")

    state.register_client("prime-wisp", "bootstrap-placeholder", replace=False)

    assert state.clients["prime-wisp"]["public_key"] == "real-public-key"


def test_relay_rejects_plaintext_application_body(tmp_path: Path) -> None:
    relay = runtime(tmp_path)
    sender = RecordingWriter()
    recipient = RecordingWriter()
    relay.sessions["android-user"] = ("token-a", sender)  # type: ignore[assignment]
    relay.sessions["prime-wisp"] = ("token-p", recipient)  # type: ignore[assignment]

    asyncio.run(
        relay.forward(
            "android-user",
            {
                "version": 1,
                "type": "envelope",
                "sender": "android-user",
                "recipient": "prime-wisp",
                "message_id": "m1",
                "algorithm": "RSA-OAEP-256+A256GCM+PS256",
                "encrypted_key": "opaque-key",
                "nonce": "opaque-nonce",
                "ciphertext": "opaque-ciphertext",
                "signature": "opaque-signature",
                "body": {"secret": "relay must never receive this"},
            },
        )
    )

    assert sender.messages == [{"ok": False, "error": "invalid_envelope"}]
    assert recipient.messages == []


def test_offline_routing_does_not_require_decrypting_application_action(tmp_path: Path) -> None:
    relay = runtime(tmp_path)
    sender = RecordingWriter()
    relay.sessions["android-user"] = ("token-a", sender)  # type: ignore[assignment]
    envelope = {
        "version": 1,
        "type": "envelope",
        "sender": "android-user",
        "recipient": "offline-wisp",
        "message_id": "m2",
        "algorithm": "RSA-OAEP-256+A256GCM+PS256",
        "encrypted_key": "opaque-key",
        "nonce": "opaque-nonce",
        "ciphertext": "opaque-ciphertext",
        "signature": "opaque-signature",
    }

    asyncio.run(relay.forward("android-user", envelope))

    assert sender.messages == [{"ok": False, "error": "recipient_offline"}]
    assert relay.state.queues == {}
