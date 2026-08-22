from __future__ import annotations

import asyncio
import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from appserve.e2e import generate_identity, public_key_text
from server.appserve_server.core import RelayConfig, RelayState
from server.appserve_server.service import RelayRuntime


def sign_auth(identity, role: str, client_id: str, challenge: str) -> str:
    transcript = f"wisp-relay-auth-v1\n{role}\n{client_id}\n{challenge}\n\n\n".encode("ascii")
    return base64.urlsafe_b64encode(identity.sign(transcript, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())).decode("ascii").rstrip("=")


def test_first_android_enrollment_is_pending_and_unclaimed(tmp_path: Path) -> None:
    state = RelayState(tmp_path / "state.json")
    first = public_key_text(generate_identity())
    second = public_key_text(generate_identity())

    assert state.enroll_client("first", first, client_kind="android") == "pending"
    assert state.enroll_client("second", second, client_kind="android") == "pending"
    assert state.clients["first"]["status"] == "pending"
    assert state.clients["first"]["admin"] is False
    assert state.clients["second"]["status"] == "pending"


def test_non_android_endpoint_cannot_claim_first_administrator(tmp_path: Path) -> None:
    state = RelayState(tmp_path / "state.json")
    python_key = public_key_text(generate_identity())
    android_key = public_key_text(generate_identity())
    assert state.enroll_client("python", python_key, client_kind="python-wisp") == "pending"
    assert state.enroll_client("android", android_key, client_kind="android") == "pending"


def test_enrollment_is_persistent_and_key_changes_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    state = RelayState(path)
    key = public_key_text(generate_identity())
    state.enroll_client("endpoint", key, client_kind="android")
    state.save()

    restored = RelayState(path)
    restored.load()
    assert restored.client_access("endpoint", key) == "pending"
    assert restored.client_access("endpoint", public_key_text(generate_identity())) == "endpoint_key_changed"


def test_claimed_administrator_persists_as_authoritative_state(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    state = RelayState(path)
    key = public_key_text(generate_identity())
    state.enroll_client("endpoint", key, client_kind="android")
    assert state.claim_admin("endpoint") == "claimed"

    restored = RelayState(path)
    restored.load()
    assert restored.clients["endpoint"]["admin"] is True
    assert restored.clients["endpoint"]["status"] == "approved"
    assert restored.claim_admin("endpoint") == "already_admin"


def test_management_state_is_server_owned_and_has_role_specific_controls(tmp_path: Path) -> None:
    state = RelayState(tmp_path / "state.json")
    runtime = RelayRuntime(RelayConfig(b"", enrollment_enabled=True), state)
    pending_key = public_key_text(generate_identity())
    other_key = public_key_text(generate_identity())
    state.enroll_client("pending", pending_key, client_kind="android")
    state.enroll_client("other", other_key, client_kind="android")

    pending = runtime.management_request("pending", {"action": "state"})
    assert pending["ok"] is True
    assert "Claim Administrator" in pending["html"]
    assert "Update server" not in pending["html"]

    assert runtime.management_request("pending", {"action": "claim_admin"})["ok"] is True
    admin = runtime.management_request("pending", {"action": "state"})
    assert "Administrator" in admin["html"]
    assert "Update server" in admin["html"]
    assert "Claim Administrator" not in admin["html"]
    assert "Approve" in admin["html"]
    assert "Revoke" in admin["html"]


def test_server_update_is_management_action_not_generic_control_action(tmp_path: Path) -> None:
    state = RelayState(tmp_path / "state.json")
    runtime = RelayRuntime(RelayConfig(b"", enrollment_enabled=True), state, update_command=("true",))
    key = public_key_text(generate_identity())
    state.enroll_client("endpoint", key, client_kind="android")
    assert runtime.management_request("endpoint", {"action": "update_server"})["error"] == "management_unauthorized"
    state.claim_admin("endpoint")
    assert runtime.management_request("endpoint", {"action": "update_server"})["ok"] is True


def test_management_operations_control_pending_endpoints_and_registered_wisps(tmp_path: Path) -> None:
    state = RelayState(tmp_path / "state.json")
    runtime = RelayRuntime(RelayConfig(b"", enrollment_enabled=True), state)
    admin_key = public_key_text(generate_identity())
    pending_key = public_key_text(generate_identity())
    state.enroll_client("admin", admin_key, client_kind="android")
    state.enroll_client("pending", pending_key, client_kind="android")

    assert runtime.management_request("admin", {"action": "claim_admin"})["ok"] is True
    assert runtime.management_request("admin", {"action": "claim_admin"})["error"] == "already_admin"
    assert runtime.management_request("admin", {"action": "list_endpoints"})["endpoints"][1]["status"] == "pending"
    assert runtime.management_request("admin", {"action": "approve", "client_id": "pending"})["ok"] is True
    assert state.client_access("pending", pending_key) == "approved"
    assert runtime.management_request("admin", {"action": "register_wisp", "id": "demo", "name": "Demo"})["ok"] is True
    assert "demo" in state.wisps
    assert runtime.management_request("admin", {"action": "remove_wisp", "id": "demo"})["ok"] is True
    assert "demo" not in state.wisps
    assert runtime.management_request("pending", {"action": "list_endpoints"})["error"] == "management_unauthorized"


def test_pending_endpoint_cannot_join_control_or_relay(tmp_path: Path) -> None:
    async def scenario() -> None:
        state = RelayState(tmp_path / "state.json")
        runtime = RelayRuntime(RelayConfig(b"", enrollment_enabled=True), state)
        first = generate_identity()
        second = generate_identity()
        state.enroll_client("admin", public_key_text(first), client_kind="android")
        server = await asyncio.start_server(runtime.handle_relay, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write((json.dumps({"type": "auth_hello", "role": "relay", "client_id": "pending", "public_key": public_key_text(second)}) + "\n").encode())
            await writer.drain()
            challenge = json.loads(await reader.readline())["challenge"]
            writer.write((json.dumps({"type": "auth_proof", "signature": sign_auth(second, "relay", "pending", challenge)}) + "\n").encode())
            await writer.drain()
            assert json.loads(await reader.readline()) == {"ok": False, "error": "endpoint_pending"}
            writer.close()
            await writer.wait_closed()
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(scenario())


def test_management_control_frame_path_is_socket_level(tmp_path: Path) -> None:
    async def scenario() -> None:
        state = RelayState(tmp_path / "state.json")
        runtime = RelayRuntime(
            RelayConfig(
                rsa.generate_private_key(65537, 2048).private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ),
                enrollment_enabled=False,
            ),
            state,
        )
        identity = generate_identity()
        state.enroll_client("android-device", public_key_text(identity), client_kind="android")
        server = await asyncio.start_server(runtime.handle_control, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write((json.dumps({"type": "auth_hello", "role": "control", "client_id": "android-device", "client_kind": "android", "public_key": public_key_text(identity)}) + "\n").encode())
            await writer.drain()
            challenge = json.loads(await reader.readline())["challenge"]
            writer.write((json.dumps({"type": "auth_proof", "signature": sign_auth(identity, "control", "android-device", challenge)}) + "\n").encode())
            await writer.drain()
            assert json.loads(await reader.readline())["ok"] is True
            writer.write((json.dumps({"type": "join", "client_id": "android-device"}) + "\n").encode())
            await writer.drain()
            joined = json.loads(await reader.readline())
            assert joined["ok"] is True
            writer.write((json.dumps({"type": "management_request", "request": {"action": "claim_admin"}}) + "\n").encode())
            await writer.drain()
            response = json.loads(await reader.readline())
            assert response["type"] == "management_response"
            assert response["ok"] is True
            assert response["status"] == "approved"
            writer.close()
            await writer.wait_closed()
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(scenario())