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


def test_relay_routes_opaque_session_envelope_after_acceptance(tmp_path: Path) -> None:
    relay = runtime(tmp_path)
    sender = RecordingWriter()
    recipient = RecordingWriter()
    relay.sessions["android-user"] = ("token-a", sender)  # type: ignore[assignment]
    relay.sessions["prime-wisp"] = ("token-p", recipient)  # type: ignore[assignment]
    envelope = {
        "version": 1, "type": "session_envelope", "session_id": "s1",
        "sender": "android-user", "recipient": "prime-wisp", "sequence": 0,
        "ciphertext": "opaque-ciphertext-and-tag",
    }

    asyncio.run(relay.forward("android-user", envelope))

    assert sender.messages == [{"ok": True, "type": "accepted", "session_id": "s1", "sequence": 0}]
    assert recipient.messages == [envelope]
    assert "master_secret" not in str(recipient.messages)


def test_relay_rejects_session_plaintext_spoofing_and_unknown_fields(tmp_path: Path) -> None:
    relay = runtime(tmp_path)
    sender = RecordingWriter()
    recipient = RecordingWriter()
    relay.sessions["android-user"] = ("token-a", sender)  # type: ignore[assignment]
    relay.sessions["prime-wisp"] = ("token-p", recipient)  # type: ignore[assignment]
    invalid = {
        "version": 1, "type": "session_envelope", "session_id": "s1",
        "sender": "attacker", "recipient": "prime-wisp", "sequence": 0,
        "ciphertext": "opaque", "body": {"secret": True},
    }

    asyncio.run(relay.forward("android-user", invalid))

    assert sender.messages == [{"ok": False, "error": "invalid_envelope"}]
    assert recipient.messages == []


def test_relay_rejects_session_sequence_outside_unsigned_64_bit_range(tmp_path: Path) -> None:
    relay = runtime(tmp_path)
    sender = RecordingWriter()
    recipient = RecordingWriter()
    relay.sessions["android-user"] = ("token-a", sender)  # type: ignore[assignment]
    relay.sessions["prime-wisp"] = ("token-p", recipient)  # type: ignore[assignment]
    invalid = {
        "version": 1, "type": "session_envelope", "session_id": "s1",
        "sender": "android-user", "recipient": "prime-wisp", "sequence": 1 << 64,
        "ciphertext": "opaque",
    }

    asyncio.run(relay.forward("android-user", invalid))

    assert sender.messages == [{"ok": False, "error": "invalid_envelope"}]
    assert recipient.messages == []


def test_bulk_relay_pairs_authenticated_peers_and_copies_exact_ciphertext(tmp_path: Path) -> None:
    async def scenario() -> None:
        relay = runtime(tmp_path)
        relay.state.clients["android-user"] = {"session_token": "android-token"}
        relay.state.clients["upload-wisp"] = {"session_token": "wisp-token"}
        server = await asyncio.start_server(relay.handle_bulk, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            receiver_reader, receiver_writer = await asyncio.open_connection("127.0.0.1", port)
            receiver_writer.write(json.dumps({
                "type": "bulk",
                "session_token": "wisp-token",
                "ticket": "one-time-ticket-1",
                "role": "receiver",
                "peer": "android-user",
                "length": 16,
            }).encode() + b"\n")
            await receiver_writer.drain()

            sender_reader, sender_writer = await asyncio.open_connection("127.0.0.1", port)
            sender_writer.write(json.dumps({
                "type": "bulk",
                "session_token": "android-token",
                "ticket": "one-time-ticket-1",
                "role": "sender",
                "peer": "upload-wisp",
                "length": 16,
            }).encode() + b"\n")
            await sender_writer.drain()

            assert json.loads(await sender_reader.readline()) == {"ok": True, "type": "bulk_ready"}
            assert json.loads(await receiver_reader.readline()) == {"ok": True, "type": "bulk_ready"}
            sender_writer.write(b"hello world12345EXTRA")
            await sender_writer.drain()

            assert await receiver_reader.readexactly(16) == b"hello world12345"
            assert json.loads(await sender_reader.readline()) == {"ok": True, "type": "bulk_complete"}

            sender_writer.close()
            receiver_writer.close()
            await sender_writer.wait_closed()
            await receiver_writer.wait_closed()

            reused_reader, reused_writer = await asyncio.open_connection("127.0.0.1", port)
            reused_writer.write(json.dumps({
                "type": "bulk",
                "session_token": "android-token",
                "ticket": "one-time-ticket-1",
                "role": "sender",
                "peer": "upload-wisp",
                "length": 16,
            }).encode() + b"\n")
            await reused_writer.drain()
            assert json.loads(await reused_reader.readline()) == {"ok": False, "error": "bulk_ticket_used"}
            reused_writer.close()
            await reused_writer.wait_closed()
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(scenario())


def test_bulk_relay_rejects_unknown_session_token(tmp_path: Path) -> None:
    async def scenario() -> None:
        relay = runtime(tmp_path)
        server = await asyncio.start_server(relay.handle_bulk, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(json.dumps({
                "type": "bulk",
                "session_token": "not-registered",
                "ticket": "ticket",
                "role": "sender",
                "peer": "upload-wisp",
                "length": 1,
            }).encode() + b"\n")
            await writer.drain()
            assert json.loads(await reader.readline()) == {"ok": False, "error": "unauthenticated"}
            writer.close()
            await writer.wait_closed()
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(scenario())


def test_bulk_relay_times_out_a_stalled_ciphertext_and_closes_both_peers(tmp_path: Path) -> None:
    async def scenario() -> None:
        relay = runtime(tmp_path)
        relay.BULK_IO_TIMEOUT_SECONDS = 0.05
        relay.state.clients["android-user"] = {"session_token": "android-token"}
        relay.state.clients["upload-wisp"] = {"session_token": "wisp-token"}
        server = await asyncio.start_server(relay.handle_bulk, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        receiver_writer = sender_writer = None
        try:
            receiver_reader, receiver_writer = await asyncio.open_connection("127.0.0.1", port)
            receiver_writer.write(json.dumps({
                "type": "bulk", "session_token": "wisp-token", "ticket": "stalled-ticket-123",
                "role": "receiver", "peer": "android-user", "length": 16,
            }).encode() + b"\n")
            await receiver_writer.drain()
            sender_reader, sender_writer = await asyncio.open_connection("127.0.0.1", port)
            sender_writer.write(json.dumps({
                "type": "bulk", "session_token": "android-token", "ticket": "stalled-ticket-123",
                "role": "sender", "peer": "upload-wisp", "length": 16,
            }).encode() + b"\n")
            await sender_writer.drain()

            assert json.loads(await sender_reader.readline()) == {"ok": True, "type": "bulk_ready"}
            assert json.loads(await receiver_reader.readline()) == {"ok": True, "type": "bulk_ready"}
            assert await asyncio.wait_for(sender_reader.read(), timeout=0.5) == b""
            assert await asyncio.wait_for(receiver_reader.read(), timeout=0.5) == b""
            assert relay.pending_bulk == {}
        finally:
            for writer in (sender_writer, receiver_writer):
                if writer is not None:
                    writer.close()
                    await writer.wait_closed()
            server.close()
            await server.wait_closed()

    asyncio.run(scenario())
