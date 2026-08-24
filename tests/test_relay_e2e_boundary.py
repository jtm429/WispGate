from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

import pytest

from appserve.e2e import generate_identity, public_key_text
from server.appserve_server.core import RelayConfig, RelayState
from server.appserve_server.service import RelayRuntime, serve


class RecordingWriter:
    def __init__(self) -> None:
        self.messages: list[dict] = []

    def write(self, data: bytes) -> None:
        self.messages.append(json.loads(data))

    async def drain(self) -> None:
        pass


class DisconnectedWriter(RecordingWriter):
    def __init__(self) -> None:
        super().__init__()
        self.closed = False

    async def drain(self) -> None:
        raise ConnectionResetError("recipient disconnected")

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        pass


def runtime(tmp_path: Path) -> RelayRuntime:
    return RelayRuntime(RelayConfig(b""), RelayState(tmp_path / "state.json"))


def test_catalog_distributes_only_enrolled_endpoint_public_keys(tmp_path: Path) -> None:
    relay = runtime(tmp_path)
    key = public_key_text(generate_identity())
    relay.state.clients["prime-wisp"] = {"public_key": key}
    relay.state.wisps["prime"] = {"id": "prime", "name": "Prime", "description": "", "owner": "prime-wisp"}
    relay.sessions["prime-wisp"] = ("prime-wisp", RecordingWriter())  # type: ignore[assignment]
    relay.relay_liveness["prime-wisp"] = time.monotonic()
    assert relay.catalog_items()[0]["public_key"] == key
    relay.state.clients["legacy"] = {"public_key": "legacy"}
    relay.state.wisps["legacy-wisp"] = {"id": "legacy-wisp", "owner": "legacy"}
    assert all(item["owner"] != "legacy" for item in relay.catalog_items())


def test_catalog_keeps_registered_wisp_with_explicit_offline_status(tmp_path: Path) -> None:
    relay = runtime(tmp_path)
    key = public_key_text(generate_identity())
    relay.state.clients["stopped-wisp"] = {"public_key": key, "status": "approved"}
    relay.state.wisps["stopped"] = {
        "id": "stopped", "name": "Stopped", "description": "", "owner": "stopped-wisp",
    }

    assert relay.catalog_items() == [{
        "id": "stopped", "name": "Stopped", "description": "", "owner": "stopped-wisp",
        "public_key": key, "online": False,
    }]


def test_catalog_broadcast_after_owner_becomes_live(tmp_path: Path) -> None:
    relay = runtime(tmp_path)
    owner_key = public_key_text(generate_identity())
    relay.state.clients["bakaneko-pi-wisp"] = {"public_key": owner_key, "status": "approved"}
    relay.state.wisps["bakaneko-desktop"] = {
        "id": "bakaneko-desktop", "name": "Bakaneko", "description": "", "owner": "bakaneko-pi-wisp",
    }
    control = RecordingWriter()
    relay.control_sessions["android-endpoint-uuid"] = ("android-endpoint-uuid", control)  # type: ignore[assignment]

    assert relay.catalog_items()[0]["id"] == "bakaneko-desktop"
    assert relay.catalog_items()[0]["online"] is False
    relay.sessions["bakaneko-pi-wisp"] = ("bakaneko-pi-wisp", RecordingWriter())  # type: ignore[assignment]
    relay.relay_liveness["bakaneko-pi-wisp"] = time.monotonic()
    asyncio.run(relay.broadcast_catalog())

    assert control.messages[0]["type"] == "catalog_update"
    assert control.messages[0]["items"][0]["id"] == "bakaneko-desktop"
    assert control.messages[0]["items"][0]["owner"] == "bakaneko-pi-wisp"
    assert control.messages[0]["items"][0]["online"] is True


def test_changed_enrolled_endpoint_key_fails_closed(tmp_path: Path) -> None:
    state = RelayState(tmp_path / "state.json")
    state.register_client("prime-wisp", "real-public-key")
    with pytest.raises(ValueError, match="changed"):
        state.register_client("prime-wisp", "replacement-key", replace=False)
    assert state.clients["prime-wisp"]["public_key"] == "real-public-key"


def test_relay_rejects_logical_sender_even_for_android_endpoint(tmp_path: Path) -> None:
    relay = runtime(tmp_path)
    sender = RecordingWriter()
    recipient = RecordingWriter()
    relay.state.clients["android-endpoint-uuid"] = {"client_kind": "android"}
    relay.sessions["android-endpoint-uuid"] = ("android-endpoint-uuid", sender)  # type: ignore[assignment]
    relay.sessions["prime-wisp"] = ("prime-wisp", recipient)  # type: ignore[assignment]
    envelope = {
        "version": 1, "type": "session_envelope", "session_id": "s1",
        "sender": "android-user", "recipient": "prime-wisp", "sequence": 0,
        "ciphertext": "opaque-ciphertext-and-tag",
    }
    asyncio.run(relay.forward("android-endpoint-uuid", envelope))
    assert sender.messages == [{"ok": False, "error": "invalid_envelope"}]
    assert recipient.messages == []


def test_relay_rejects_android_logical_sender_from_non_android_endpoint(tmp_path: Path) -> None:
    relay = runtime(tmp_path)
    sender = RecordingWriter()
    recipient = RecordingWriter()
    relay.state.clients["python-wisp"] = {"client_kind": "python"}
    relay.sessions["python-wisp"] = ("python-wisp", sender)  # type: ignore[assignment]
    relay.sessions["prime-wisp"] = ("prime-wisp", recipient)  # type: ignore[assignment]
    envelope = {
        "version": 1, "type": "session_envelope", "session_id": "s1",
        "sender": "android-user", "recipient": "prime-wisp", "sequence": 0,
        "ciphertext": "opaque-ciphertext-and-tag",
    }
    asyncio.run(relay.forward("python-wisp", envelope))
    assert sender.messages == [{"ok": False, "error": "invalid_envelope"}]
    assert recipient.messages == []


def test_destination_write_failure_does_not_terminate_source_session(tmp_path: Path) -> None:
    relay = runtime(tmp_path)
    source = RecordingWriter()
    destination = DisconnectedWriter()
    relay.sessions["collector-wisp"] = ("collector-wisp", source)  # type: ignore[assignment]
    relay.sessions["android-user"] = ("android-user", destination)  # type: ignore[assignment]
    envelope = {
        "version": 1, "type": "session_envelope", "session_id": "s1",
        "sender": "collector-wisp", "recipient": "android-user", "sequence": 0,
        "ciphertext": "opaque-final-response",
    }
    asyncio.run(relay.forward("collector-wisp", envelope))
    assert relay.sessions["collector-wisp"] == ("collector-wisp", source)
    assert "android-user" not in relay.sessions
    assert destination.closed


def test_production_serve_requires_tls_certificate_and_key(tmp_path: Path) -> None:
    relay = runtime(tmp_path)

    async def scenario() -> None:
        with pytest.raises(ValueError, match="require TLS"):
            await serve(relay, "127.0.0.1", 0, "127.0.0.1", 0, bulk_host="127.0.0.1", bulk_port=0)

    asyncio.run(scenario())
