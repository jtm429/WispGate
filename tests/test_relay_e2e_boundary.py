from __future__ import annotations

import asyncio
import json
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
    assert relay.catalog_items()[0]["public_key"] == key
    relay.state.clients["legacy"] = {"public_key": "legacy"}
    relay.state.wisps["legacy-wisp"] = {"id": "legacy-wisp", "owner": "legacy"}
    assert all(item["owner"] != "legacy" for item in relay.catalog_items())


def test_changed_enrolled_endpoint_key_fails_closed(tmp_path: Path) -> None:
    state = RelayState(tmp_path / "state.json")
    state.register_client("prime-wisp", "real-public-key")
    with pytest.raises(ValueError, match="changed"):
        state.register_client("prime-wisp", "replacement-key", replace=False)
    assert state.clients["prime-wisp"]["public_key"] == "real-public-key"


def test_relay_routes_opaque_session_envelope_after_acceptance(tmp_path: Path) -> None:
    relay = runtime(tmp_path)
    sender = RecordingWriter()
    recipient = RecordingWriter()
    relay.sessions["android-user"] = ("android-user", sender)  # type: ignore[assignment]
    relay.sessions["prime-wisp"] = ("prime-wisp", recipient)  # type: ignore[assignment]
    envelope = {
        "version": 1, "type": "session_envelope", "session_id": "s1",
        "sender": "android-user", "recipient": "prime-wisp", "sequence": 0,
        "ciphertext": "opaque-ciphertext-and-tag",
    }
    asyncio.run(relay.forward("android-user", envelope))
    assert sender.messages == [{"ok": True, "type": "accepted", "session_id": "s1", "sequence": 0}]
    assert recipient.messages == [envelope]
    assert "body" not in str(recipient.messages)


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
