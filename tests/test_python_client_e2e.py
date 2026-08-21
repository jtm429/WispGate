from __future__ import annotations

import asyncio
import base64
import json
import logging
import threading
from pathlib import Path

from appserve.client import (
    AppserveClient,
    ServerInfo,
    Wisp,
    WispAction,
    WispAsset,
    WispResponse,
    _IncomingTransfer,
)
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
    # Unit tests inject a relay writer directly instead of completing _serve_once.
    # Production readiness remains controlled exclusively by the relay handshake.
    client._relay_ready.set()
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

    return ServerInfo("localhost", 1, 2, base64.urlsafe_b64decode(public), "0" * 64), config


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


def test_event_loop_replies_to_transport_ping_without_dispatching_application_data(tmp_path: Path) -> None:
    identity = generate_identity()
    info, _ = make_info(tmp_path)
    client = AppserveClient(info, "prime-wisp", identity_key=identity)
    writer = RecordingWriter()

    async def scenario() -> None:
        reader = asyncio.StreamReader()
        reader.feed_data(b'{"type":"ping","nonce":"heartbeat-1"}\n')
        reader.feed_data(b'{"type":"pong","nonce":"heartbeat-2"}\n')
        reader.feed_eof()
        client._reader = reader
        client._writer = writer  # type: ignore[assignment]
        await client._event_loop()

    asyncio.run(scenario())

    assert writer.messages == [{"type": "pong", "nonce": "heartbeat-1"}]


def test_heartbeat_loop_sends_protocol_ping_while_relay_is_idle(tmp_path: Path) -> None:
    identity = generate_identity()
    info, _ = make_info(tmp_path)
    client = AppserveClient(info, "prime-wisp", identity_key=identity)
    writer = RecordingWriter()
    client.HEARTBEAT_INTERVAL_SECONDS = 0.01

    async def scenario() -> None:
        client._writer = writer  # type: ignore[assignment]
        client._relay_ready.set()
        task = asyncio.create_task(client._heartbeat_loop())
        for _ in range(20):
            if writer.messages:
                break
            await asyncio.sleep(0.005)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    asyncio.run(scenario())

    assert writer.messages[0]["type"] == "ping"
    assert isinstance(writer.messages[0]["nonce"], str)


def test_completed_file_operation_can_be_resumed_without_rerunning_wisp(tmp_path: Path) -> None:
    identity = generate_identity()
    info, _ = make_info(tmp_path)
    client = AppserveClient(info, "prime-wisp", identity_key=identity)
    client.register(Wisp("upload", "Upload", "", state=lambda: {}, action=lambda _: {}))
    sent: list[dict] = []

    async def record(_recipient: str, body: dict) -> None:
        sent.append(body)

    client._send_session = record  # type: ignore[method-assign]
    client._remember_completed_operation(
        "android-user", "transfer-1", {"wisp_id": "upload", "response": {"html": "<p>done</p>"}},
    )

    asyncio.run(client._dispatch_session_body("android-user", {
        "wisp_id": "upload", "action": "operation_resume", "operation_id": "transfer-1",
    }))

    assert sent == [{
        "wisp_id": "upload",
        "response": {"html": "<p>done</p>"},
        "operation": {"type": "completed", "operation_id": "transfer-1"},
    }]


def test_active_non_file_operation_resumes_as_running(tmp_path: Path) -> None:
    identity = generate_identity()
    info, _ = make_info(tmp_path)
    client = AppserveClient(info, "counter-wisp", identity_key=identity)
    client.register(Wisp("counter", "Counter", "", state=lambda: {}, action=lambda _: {}))
    client._active_operations.add(("android-user", "operation-1"))
    sent: list[dict] = []

    async def record(_recipient: str, body: dict) -> None:
        sent.append(body)

    client._send_session = record  # type: ignore[method-assign]
    asyncio.run(client._dispatch_session_body("android-user", {
        "wisp_id": "counter", "action": "operation_resume", "operation_id": "operation-1",
    }))

    assert sent == [{
        "wisp_id": "counter",
        "operation": {"type": "running", "operation_id": "operation-1"},
    }]


def test_duplicate_mutating_action_with_same_operation_id_executes_once(tmp_path: Path) -> None:
    identity = generate_identity()
    info, _ = make_info(tmp_path)
    client = AppserveClient(info, "counter-wisp", identity_key=identity)
    calls = 0
    sent: list[dict] = []

    def mutate(_: WispAction) -> dict[str, str]:
        nonlocal calls
        calls += 1
        return {"html": f"<p>{calls}</p>"}

    async def record(_recipient: str, body: dict) -> None:
        sent.append(body)

    client.register(Wisp("counter", "Counter", "", state=lambda: {}, action=mutate))
    client._send_session = record  # type: ignore[method-assign]
    request = {
        "wisp_id": "counter",
        "action": "increment",
        "operation_id": "stable-operation-1",
        "action_data": {},
    }

    async def scenario() -> None:
        await client._dispatch_session_body("android-user", request)
        await client._dispatch_session_body("android-user", request)

    asyncio.run(scenario())

    assert calls == 1
    assert sent == [
        {"wisp_id": "counter", "response": {"html": "<p>1</p>"}},
        {"wisp_id": "counter", "response": {"html": "<p>1</p>"}},
    ]


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


def test_sync_wisp_action_does_not_block_the_relay_event_loop(tmp_path: Path) -> None:
    identity = generate_identity()
    info, _ = make_info(tmp_path)
    client = AppserveClient(info, "blocking-wisp", identity_key=identity)
    release = threading.Event()
    observed: dict[str, bool] = {}

    def blocking_action(_: WispAction) -> dict[str, str]:
        observed["released_by_event_loop"] = release.wait(timeout=0.5)
        return {"html": "<p>done</p>"}

    client.register(Wisp("blocking", "Blocking", "", state=lambda: {"html": ""}, action=blocking_action))

    async def discard_response(*_args: object) -> None:
        pass

    client._send_wisp_response = discard_response  # type: ignore[method-assign]

    async def scenario() -> None:
        task = asyncio.create_task(client._dispatch_session_body("android-user", {
            "wisp_id": "blocking",
            "action": "invoke",
            "operation_id": "blocking-operation-1",
            "action_data": {},
        }))
        await asyncio.sleep(0.01)
        release.set()
        await task

    asyncio.run(scenario())

    assert observed == {"released_by_event_loop": True}


def test_inflight_file_action_survives_relay_reconnect(tmp_path: Path) -> None:
    android = generate_identity()
    wisp_identity = generate_identity()
    info, _ = make_info(tmp_path)
    client = AppserveClient(info, "prime-wisp", identity_key=wisp_identity)

    async def scenario() -> dict:
        first_writer = RecordingWriter()
        client._writer = first_writer  # type: ignore[assignment]
        android_session = await establish_peer_session(client, android, wisp_identity)
        release = asyncio.Event()

        async def finish_after_reconnect() -> None:
            await release.wait()
            await client._send_session("android-user", {"type": "complete"})

        task = asyncio.create_task(finish_after_reconnect())
        transfer = _IncomingTransfer(
            "android-user",
            Wisp("upload", "Upload", "", state=lambda: {}, action=lambda _: {}),
            {},
            tmp_path / "transfer",
            {},
            0.0,
            task,
        )
        client._transfers[("android-user", "transfer-1")] = transfer

        client._close_connection()
        await asyncio.sleep(0)
        assert not task.cancelled()
        assert client._transfers[("android-user", "transfer-1")] is transfer
        assert "android-user" in client._peer_sessions

        replacement_writer = RecordingWriter()
        client._writer = replacement_writer  # type: ignore[assignment]
        client._relay_ready.set()
        release.set()
        await task

        return android_session.decrypt(
            replacement_writer.messages[0],
            now=client._peer_sessions["android-user"].created_at + 1,
        )

    assert asyncio.run(scenario()) == {"type": "complete"}


def test_inflight_completion_waits_for_reconnected_relay(tmp_path: Path) -> None:
    android = generate_identity()
    wisp_identity = generate_identity()
    info, _ = make_info(tmp_path)
    client = AppserveClient(info, "prime-wisp", identity_key=wisp_identity)

    async def scenario() -> dict:
        client._writer = RecordingWriter()  # type: ignore[assignment]
        android_session = await establish_peer_session(client, android, wisp_identity)
        client._close_connection()

        completion = asyncio.create_task(
            client._send_session("android-user", {"type": "complete"})
        )
        await asyncio.sleep(0)
        assert not completion.done()

        replacement_writer = RecordingWriter()
        client._writer = replacement_writer  # type: ignore[assignment]
        client._relay_ready.set()
        await completion
        return android_session.decrypt(
            replacement_writer.messages[0],
            now=client._peer_sessions["android-user"].created_at + 1,
        )

    assert asyncio.run(scenario()) == {"type": "complete"}


def test_waiting_completion_encrypts_with_replacement_peer_session(tmp_path: Path) -> None:
    android = generate_identity()
    wisp_identity = generate_identity()
    info, _ = make_info(tmp_path)
    client = AppserveClient(info, "prime-wisp", identity_key=wisp_identity)

    async def scenario() -> dict:
        client._writer = RecordingWriter()  # type: ignore[assignment]
        old_peer = await establish_peer_session(client, android, wisp_identity)
        created_at = client._peer_sessions["android-user"].created_at
        client._relay_ready.clear()

        completion = asyncio.create_task(client._send_session("android-user", {"type": "complete"}))
        await asyncio.sleep(0)

        master = bytes(reversed(range(32)))
        android_to_wisp, wisp_to_android = derive_session_keys(master, "replacement-session")
        client._peer_sessions["android-user"] = PeerSession(
            "replacement-session", "prime-wisp", "android-user",
            android_to_wisp, wisp_to_android, created_at=created_at,
        )
        replacement_peer = PeerSession(
            "replacement-session", "android-user", "prime-wisp",
            android_to_wisp, wisp_to_android, created_at=created_at,
        )
        replacement_writer = RecordingWriter()
        client._writer = replacement_writer  # type: ignore[assignment]
        client._relay_ready.set()
        await completion

        assert old_peer.session_id != replacement_peer.session_id
        return replacement_peer.decrypt(replacement_writer.messages[0], now=created_at + 1)

    assert asyncio.run(scenario()) == {"type": "complete"}


def test_expiring_active_transfer_cancels_task_before_deleting_files(tmp_path: Path) -> None:
    identity = generate_identity()
    info, _ = make_info(tmp_path)
    client = AppserveClient(info, "upload-wisp", identity_key=identity)
    transfer_dir = tmp_path / "active-transfer"
    transfer_dir.mkdir()
    (transfer_dir / "0.upload").write_bytes(b"still-in-use")
    observed: dict[str, bool] = {}

    async def scenario() -> None:
        async def worker() -> None:
            try:
                await asyncio.Event().wait()
            finally:
                observed["files_existed_during_task_cleanup"] = transfer_dir.exists()

        task = asyncio.create_task(worker())
        await asyncio.sleep(0)
        transfer = _IncomingTransfer(
            "android-user",
            Wisp("upload", "Upload", "", state=lambda: {}, action=lambda _: {}),
            {}, transfer_dir, {}, 0.0, task,
        )
        client._transfers[("android-user", "expired-transfer")] = transfer
        await client._dispatch_session_body("android-user", {"wisp_id": "missing"})
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

        assert task.cancelled()
        assert ("android-user", "expired-transfer") not in client._transfers
        assert not transfer_dir.exists()

    asyncio.run(scenario())

    assert observed == {"files_existed_during_task_cleanup": True}


def test_expired_file_operation_returns_indeterminate_without_restarting(tmp_path: Path) -> None:
    identity = generate_identity()
    info, _ = make_info(tmp_path)
    client = AppserveClient(info, "upload-wisp", identity_key=identity)
    wisp = Wisp("upload", "Upload", "", state=lambda: {}, action=lambda _: {})
    client.register(wisp)
    transfer_dir = tmp_path / "expired-transfer"
    transfer_dir.mkdir()
    client._transfers[("android-user", "stable-file-operation")] = _IncomingTransfer(
        "android-user", wisp, {}, transfer_dir, {}, 0.0,
    )
    begin_calls = 0
    sent: list[dict] = []

    def unexpected_begin(*_args: object) -> dict:
        nonlocal begin_calls
        begin_calls += 1
        return {}

    async def record(_recipient: str, body: dict) -> None:
        sent.append(body)

    client._begin_file_action = unexpected_begin  # type: ignore[method-assign]
    client._send_session = record  # type: ignore[method-assign]

    asyncio.run(client._dispatch_session_body("android-user", {
        "wisp_id": "upload",
        "action": "file_begin",
        "transfer_id": "stable-file-operation",
        "action_data": {},
        "files": [{}],
    }))

    assert begin_calls == 0
    assert sent == [{
        "wisp_id": "upload",
        "operation": {"type": "indeterminate", "operation_id": "stable-file-operation"},
    }]


def test_successful_file_callback_is_retained_when_delivery_fails(tmp_path: Path) -> None:
    identity = generate_identity()
    info, _ = make_info(tmp_path)
    client = AppserveClient(info, "upload-wisp", identity_key=identity)
    transfer_dir = tmp_path / "completed-transfer"
    transfer_dir.mkdir()
    wisp = Wisp(
        "upload", "Upload", "", state=lambda: {},
        action=lambda _: {"html": "<p>executed successfully</p>"},
    )
    transfer = _IncomingTransfer(
        "android-user", wisp, {}, transfer_dir, {}, 0.0,
    )
    client._transfers[("android-user", "delivery-failure")] = transfer

    async def fail_delivery(*_args: object) -> None:
        raise ConnectionError("relay disconnected after callback")

    async def discard(*_args: object) -> None:
        pass

    client._send_wisp_response = fail_delivery  # type: ignore[method-assign]
    client._send_session = discard  # type: ignore[method-assign]

    asyncio.run(client._receive_bulk_transfer("delivery-failure", transfer))

    assert client._completed_operations[("android-user", "delivery-failure")][1] == {
        "wisp_id": "upload",
        "response": {"html": "<p>executed successfully</p>"},
    }


def test_asset_completion_leaves_non_replayable_tombstone(tmp_path: Path) -> None:
    identity = generate_identity()
    info, _ = make_info(tmp_path)
    client = AppserveClient(info, "asset-wisp", identity_key=identity)
    transfer_dir = tmp_path / "asset-transfer"
    transfer_dir.mkdir()
    state = WispResponse(
        "<p>asset generated</p>",
        assets=(WispAsset.from_bytes("result", "result.txt", "text/plain", b"once"),),
    )
    wisp = Wisp("asset", "Asset", "", state=lambda: {}, action=lambda _: state)
    transfer = _IncomingTransfer("android-user", wisp, {}, transfer_dir, {}, 0.0)
    client._transfers[("android-user", "asset-operation")] = transfer

    async def fail_delivery(*_args: object) -> None:
        raise ConnectionError("asset delivery failed")

    client._send_wisp_response = fail_delivery  # type: ignore[method-assign]

    asyncio.run(client._receive_bulk_transfer("asset-operation", transfer))

    assert client._completed_operations[("android-user", "asset-operation")][1] == {
        "wisp_id": "asset",
        "operation": {"type": "indeterminate", "operation_id": "asset-operation"},
    }
