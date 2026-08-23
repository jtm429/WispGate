from __future__ import annotations

import asyncio
import base64
import html
import json
import logging
import secrets
import ssl
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .core import (
    RelayConfig, RelayState, parse_bootstrap, decrypt_bootstrap_request,
    build_bootstrap_response,
)

LOG = logging.getLogger("appserve.relay")


def create_server_ssl_context(cert_path: str | Path, key_path: str | Path) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    return context


def valid_endpoint_public_key(value: str) -> bool:
    try:
        encoded = value + "=" * (-len(value) % 4)
        key = serialization.load_der_public_key(base64.urlsafe_b64decode(encoded))
        return isinstance(key, rsa.RSAPublicKey) and key.key_size >= 2048
    except (ValueError, TypeError, base64.binascii.Error):
        return False


@dataclass
class RelayRuntime:
    config: RelayConfig
    state: RelayState
    sessions: dict[str, tuple[str, asyncio.StreamWriter]] = field(default_factory=dict)
    relay_liveness: dict[str, float] = field(default_factory=dict)
    control_sessions: dict[str, tuple[str, asyncio.StreamWriter]] = field(default_factory=dict)
    update_command: tuple[str, ...] | None = None
    server_version: str = "unknown"
    pending_bulk: dict[str, "_BulkConnection"] = field(default_factory=dict)
    consumed_bulk: dict[str, float] = field(default_factory=dict)
    bulk_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    auth_challenges: dict[str, tuple[str, str, str, str, float]] = field(default_factory=dict)
    certificate_der: bytes | None = None

    MAX_BULK_BYTES = 256 * 1024 * 1024 + 16
    MAX_PENDING_BULK = 128
    BULK_TICKET_TTL_SECONDS = 10 * 60
    BULK_IO_TIMEOUT_SECONDS = 10 * 60
    RELAY_LINE_LIMIT_BYTES = 1024 * 1024 + 16 * 1024
    HEARTBEAT_TIMEOUT_SECONDS = 75

    def catalog_items(self, client_id: str | None = None) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        if client_id and self.state.clients.get(client_id) and self._endpoint_usable(client_id, include_pending=True):
            items.append({"id": "management", "name": "Management", "description": "Claim administrator access and manage server Wisps", "owner": "__server__", "public_key": self.config.public_key_text()})
        for manifest in self.state.wisps.values():
            owner = manifest.get("owner")
            # ``state.wisps`` is durable registration metadata, not an online
            # presence list.  Only advertise a Wisp while its runtime has a
            # live relay session; otherwise clients retain dead/stale Wisps
            # after an endpoint has stopped or before it has connected.
            if not owner or not self._relay_online(owner):
                continue
            if client_id and not self._endpoint_usable(client_id):
                continue
            if owner and not self._endpoint_usable(owner):
                continue
            public_key = self.state.clients.get(owner, {}).get("public_key")
            if not public_key or not valid_endpoint_public_key(public_key):
                continue
            items.append({**manifest, "public_key": public_key})
        return items

    def _endpoint_usable(self, client_id: str, *, include_pending: bool = False) -> bool:
        status = self.state.clients.get(client_id, {}).get("status", "approved")
        return status == "approved" or (include_pending and status == "pending")

    def _relay_online(self, client_id: str) -> bool:
        last_seen = self.relay_liveness.get(client_id)
        return last_seen is not None and time.monotonic() - last_seen <= self.HEARTBEAT_TIMEOUT_SECONDS

    def _is_admin(self, client_id: str) -> bool:
        record = self.state.clients.get(client_id, {})
        return bool(record.get("admin")) and self._endpoint_usable(client_id)

    def management_request(self, client_id: str, request: dict[str, Any]) -> dict[str, Any]:
        action = request.get("action")
        if action in {"state", "status"}:
            record = self.state.clients.get(client_id)
            if record is None:
                return {"ok": False, "error": "unknown_endpoint"}
            if action == "status":
                return {"ok": True, "client_id": client_id, **record}
            admin = self._is_admin(client_id)
            endpoints = [{"client_id": key, **value} for key, value in self.state.clients.items()] if admin else []
            # The renderer needs the authoritative endpoint identity so it can
            # avoid offering self-destructive controls for the administrator.
            record = {"client_id": client_id, **record}
            wisps = [
                manifest
                for manifest in self.state.wisps.values()
                if self._relay_online(manifest.get("owner", ""))
            ] if admin else []
            return {
                "ok": True,
                "client_id": client_id,
                **record,
                "html": self._management_html(record, endpoints, wisps, admin=admin),
            }
        if action == "claim_admin":
            result = self.state.claim_admin(client_id)
            if result == "claimed":
                return {"ok": True, "status": "approved", "admin": True}
            if result == "already_admin":
                return {"ok": True, "status": "approved", "admin": True, "error": "already_admin"}
            if result == "admin_already_claimed":
                return {"ok": False, "error": "admin_already_claimed"}
            return {"ok": False, "error": result}
        if not self._is_admin(client_id):
            return {"ok": False, "error": "management_unauthorized"}
        if action == "current_server_version":
            return {"ok": True, "type": "server_version", "version": self.server_version}
        if action == "update_server":
            if not self.update_command:
                LOG.error("server update requested but no update command is configured")
                return {"ok": False, "error": "update_unconfigured"}
            try:
                subprocess.Popen(self.update_command, start_new_session=True)
            except OSError:
                LOG.exception("unable to launch configured server update command: %s", self.update_command)
                return {"ok": False, "error": "update_launch_failed"}
            LOG.info("server update requested by administrator")
            return {"ok": True, "type": "update_started"}
        if action == "list_endpoints":
            return {"ok": True, "endpoints": [{"client_id": key, **value} for key, value in self.state.clients.items()]}
        if action in {"approve", "reject", "revoke"}:
            target = request.get("client_id")
            if not isinstance(target, str) or target == client_id:
                return {"ok": False, "error": "invalid_endpoint"}
            try:
                self.state.set_client_status(target, {"approve": "approved", "reject": "rejected", "revoke": "revoked"}[action])
            except KeyError:
                return {"ok": False, "error": "unknown_endpoint"}
            if action != "approve":
                self.state.remove_wisps_for_owner(target)
                for table in (self.sessions, self.control_sessions):
                    session = table.pop(target, None)
                    if session:
                        session[1].close()
            return {"ok": True, "client_id": target, "status": self.state.clients[target]["status"]}
        if action == "inspect_endpoint":
            target = request.get("client_id")
            record = self.state.clients.get(target)
            return {"ok": True, "client_id": target, **record} if record else {"ok": False, "error": "unknown_endpoint"}
        if action == "list_wisps":
            return {"ok": True, "wisps": list(self.state.wisps.values())}
        if action == "register_wisp":
            wisp_id = request.get("id")
            if not isinstance(wisp_id, str) or not wisp_id or wisp_id == "management" or wisp_id in self.state.wisps:
                return {"ok": False, "error": "invalid_wisp"}
            self.state.wisps[wisp_id] = {"id": wisp_id, "name": request.get("name", wisp_id), "description": request.get("description", ""), "owner": request.get("owner", client_id)}
            self.state.save()
            return {"ok": True, "wisp": self.state.wisps[wisp_id]}
        if action == "remove_wisp":
            wisp_id = request.get("id")
            if wisp_id not in self.state.wisps:
                return {"ok": False, "error": "unknown_wisp"}
            self.state.wisps.pop(wisp_id)
            self.state.save()
            return {"ok": True, "id": wisp_id}
        return {"ok": False, "error": "unknown_management_action"}

    def _management_html(self, record: dict[str, Any], endpoints: list[dict[str, Any]], wisps: list[dict[str, Any]], *, admin: bool) -> str:
        esc = html.escape

        def button(action: dict[str, Any], label: str) -> str:
            # Encode the JSON action as a JavaScript string; the native host remains generic.
            value = esc(json.dumps(json.dumps(action, separators=(",", ":"))), quote=True)
            return f'<button onclick="_WispGateNative.submit({value})">{esc(label)}</button>'

        status = esc(str(record.get("status", "unknown")))
        out = ["<main><h1>Management</h1>", f"<p>Status: <strong>{status}</strong>"]
        if admin:
            out.append(" · Administrator</p><h2>Server administration</h2>")
            out.append(
                '<p>Server version: <code>'
                + esc(self.server_version)
                + "</code></p><p>"
                + button({"action": "current_server_version"}, "Current server version")
                + " "
                + button({"action": "update_server"}, "Update server")
                + "</p>"
            )
            out.append("<h2>Endpoints</h2><ul>")
            for endpoint in sorted(endpoints, key=lambda item: item.get("client_id", "")):
                client_id = str(endpoint.get("client_id", ""))
                item = f"<li><code>{esc(client_id)}</code>: {esc(str(endpoint.get('status', 'unknown')))}"
                if client_id != record.get("client_id"):
                    endpoint_status = endpoint.get("status")
                    if endpoint_status != "approved":
                        item += button({"action": "approve", "client_id": client_id}, "Approve")
                    if endpoint_status != "rejected":
                        item += button({"action": "reject", "client_id": client_id}, "Reject")
                    if endpoint_status != "revoked":
                        item += button({"action": "revoke", "client_id": client_id}, "Revoke")
                out.append(item + "</li>")
            out.append("</ul><h2>Active Wisps</h2><ul>")
            for wisp in sorted(wisps, key=lambda item: item.get("id", "")):
                wisp_id = str(wisp.get("id", ""))
                out.append(
                    f"<li><strong>{esc(str(wisp.get('name', wisp_id)))}</strong> "
                    f"<code>{esc(wisp_id)}</code> {button({'action': 'remove_wisp', 'id': wisp_id}, 'Remove')}</li>"
                )
            out.append("</ul>")
        else:
            out.append("</p>")
            if record.get("status") == "pending" and not record.get("admin"):
                out.append(button({"action": "claim_admin"}, "Claim Administrator"))
            else:
                out.append("<p>Administrator access is not available for this endpoint.</p>")
        return "".join(out) + "</main>"

    async def handle_control(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        client_id = None
        try:
            auth = json.loads(await asyncio.wait_for(reader.readline(), timeout=15))
            if auth.get("type") == "bootstrap_request":
                if self.certificate_der is None:
                    await send_json(writer, {"ok": False, "error": "bootstrap_unavailable"})
                    return
                request = decrypt_bootstrap_request(
                    self.config.private_key(), auth["payload"].encode("ascii")
                )
                client_id = request["client_id"]
                client_kind = request.get("client_kind", "unknown")
                client_key = request["client_public_key"]
                encoded_key = base64.urlsafe_b64encode(client_key.public_bytes(
                    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
                )).decode("ascii").rstrip("=")
                access = self.state.client_access(client_id, encoded_key)
                if access == "unknown_endpoint" and self.config.enrollment_enabled:
                    self.state.enroll_client(client_id, encoded_key, client_kind=client_kind)
                elif access not in {"approved", "admin", "pending"}:
                    await send_json(writer, {"ok": False, "error": "endpoint_" + access})
                    return
                response = build_bootstrap_response(
                    client_key, request["nonce"], self.certificate_der
                )
                await send_json(writer, {"ok": True, "type": "bootstrap_response", "payload": response.decode("ascii")})
                auth = json.loads(await asyncio.wait_for(reader.readline(), timeout=15))
            client_id = await self._authenticate_endpoint(
                reader, writer, auth, allowed_roles={"control"}, allow_pending_control=True,
            )
            if client_id is None:
                return
            line = await asyncio.wait_for(reader.readline(), timeout=15)
            request = json.loads(line)
            if request.get("type") == "management_request":
                await send_json(writer, {"type": "management_response", **self.management_request(client_id, request.get("request", {}))})
                return
            if request.get("type") != "join":
                await send_json(writer, {"ok": False, "error": "invalid_bootstrap"})
                return
            if request.get("payload"):
                payload = parse_bootstrap(self.config, request["payload"].encode("ascii"))
                if payload["client_id"] != client_id:
                    raise ValueError("join client mismatch")
                client_id = payload["client_id"]
            elif request.get("client_id") != client_id:
                raise ValueError("join client mismatch")
            self.state.save()
            await send_json(
                writer,
                {
                    "ok": True,
                    "type": "joined",
                    "client_id": client_id,

                    "queued": len(self.state.queues.get(client_id, [])),
                    "wisps": self.catalog_items(client_id),
                },
            )
            registration = await asyncio.wait_for(reader.readline(), timeout=2)
            if registration:
                message = json.loads(registration)
                if message.get("type") == "management_request":
                    await send_json(writer, {"type": "management_response", **self.management_request(client_id, message.get("request", {}))})
                    return
                if message.get("type") == "wisps":
                    items = message.get("items", [])
                    LOG.info(
                        "wisp registration received client_id=%s type=%s item_count=%d item_ids=%s item_owners=%s item_public_key_present=%s client_public_key_present=%s state_wisps_before=%s",
                        client_id,
                        message.get("type"),
                        len(items) if isinstance(items, list) else -1,
                        [item.get("id") for item in items if isinstance(item, dict)],
                        [item.get("owner") for item in items if isinstance(item, dict)],
                        [bool(item.get("public_key")) for item in items if isinstance(item, dict)],
                        bool(message.get("client_public_key")),
                        sorted(self.state.wisps.keys()),
                    )
                    if message.get("client_public_key"):
                        self.state.register_client(client_id, message["client_public_key"])
                    self.state.remove_wisps_for_owner(client_id)
                    for item in items:
                        if item.get("id"):
                            self.state.wisps[item["id"]] = {
                                "id": item["id"],
                                "name": item.get("name", item["id"]),
                                "description": item.get("description", ""),
                                "owner": client_id,
                            }
                    self.state.save()
                    catalog = self.catalog_items(client_id)
                    LOG.info(
                        "wisp registration applied client_id=%s state_wisps_after=%s catalog_ids=%s",
                        client_id,
                        sorted(self.state.wisps.keys()),
                        [item.get("id") for item in catalog],
                    )
                    await send_json(writer, {"ok": True, "type": "wisps_registered", "items": catalog})
                    await self.broadcast_catalog()
                    if self._is_admin(client_id) or self.state.clients.get(client_id, {}).get("status") == "pending":
                        if self._is_admin(client_id):
                            self.control_sessions[client_id] = (client_id, writer)
                        while line := await asyncio.wait_for(
                            reader.readline(), timeout=self.HEARTBEAT_TIMEOUT_SECONDS
                        ):
                            control_message = json.loads(line)
                            if control_message.get("type") == "ping":
                                nonce = control_message.get("nonce")
                                if isinstance(nonce, str) and 1 <= len(nonce) <= 128:
                                    await send_json(writer, {"type": "pong", "nonce": nonce})
                            elif control_message.get("type") == "management_request":
                                response = self.management_request(client_id, control_message.get("request", {}))
                                await send_json(writer, {"type": "management_response", **response})

            LOG.info("client joined: %s from %s", client_id, peer)
        except (KeyError, ValueError, json.JSONDecodeError, base64.binascii.Error, asyncio.TimeoutError) as exc:
            LOG.warning("rejected join from %s: %s", peer, exc)
            await send_json(writer, {"ok": False, "error": "invalid_bootstrap"})
        finally:
            if client_id and self.control_sessions.get(client_id, (None, None))[1] is writer:
                self.control_sessions.pop(client_id, None)
            writer.close()
            await writer.wait_closed()

    async def broadcast_catalog(self) -> None:
        message = {"ok": True, "type": "catalog_update", "items": self.catalog_items()}
        LOG.info("broadcasting catalog_update items=%s control_clients=%s", [item.get("id") for item in message["items"]], sorted(self.control_sessions))
        stale: list[str] = []
        for client_id, (_, writer) in list(self.control_sessions.items()):
            try:
                await send_json(writer, {"ok": True, "type": "catalog_update", "items": self.catalog_items(client_id)})
            except (ConnectionError, OSError):
                stale.append(client_id)
        for client_id in stale:
            self.control_sessions.pop(client_id, None)


    async def handle_relay(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        client_id = None
        try:
            hello = json.loads(await asyncio.wait_for(reader.readline(), timeout=15))
            client_id = await self._authenticate_endpoint(reader, writer, hello, allowed_roles={"relay"})
            if client_id is None:
                return
            self.sessions[client_id] = (client_id, writer)
            self.relay_liveness[client_id] = time.monotonic()
            self.state.clients[client_id]["last_seen"] = int(asyncio.get_running_loop().time())
            await send_json(writer, {"ok": True, "type": "ready", "client_id": client_id})
            for queued in self.state.drain(client_id):
                await send_json(writer, queued)
            self.state.save()
            LOG.info("relay connected: %s from %s", client_id, peer)
            await self.broadcast_catalog()
            while line := await asyncio.wait_for(
                reader.readline(), timeout=self.HEARTBEAT_TIMEOUT_SECONDS
            ):
                self.relay_liveness[client_id] = time.monotonic()
                message = json.loads(line)
                if message.get("type") == "ping":
                    nonce = message.get("nonce")
                    if isinstance(nonce, str) and 1 <= len(nonce) <= 128:
                        await send_json(writer, {"type": "pong", "nonce": nonce})
                    else:
                        await send_json(writer, {"ok": False, "error": "invalid_heartbeat"})
                    continue
                if message.get("type") == "pong":
                    continue
                if message.get("type") not in {"envelope", "session_envelope", "session_reset"}:
                    await send_json(writer, {"ok": False, "error": "invalid_envelope"})
                    continue
                await self.forward(client_id, message)
            LOG.info("relay connection EOF for %s", client_id or peer)
        except (asyncio.TimeoutError, ConnectionError, json.JSONDecodeError) as exc:
            LOG.info("relay connection ended for %s: %s", client_id or peer, exc)
        finally:
            if client_id and self.sessions.get(client_id, (None, None))[1] is writer:
                self.sessions.pop(client_id, None)
                self.relay_liveness.pop(client_id, None)
                LOG.info("relay session offline for %s; retaining durable Wisp registrations", client_id)
                await self.broadcast_catalog()
            writer.close()
            await writer.wait_closed()

    async def _authenticate_endpoint(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, hello: dict[str, Any],
        *, allowed_roles: set[str], allow_enrollment: bool = True, allow_pending_control: bool = False,
    ) -> str | None:
        role = hello.get("role")
        client_id = hello.get("client_id")
        public_key = hello.get("public_key")
        client_kind = hello.get("client_kind", "unknown")
        ticket = hello.get("ticket", "")
        peer = hello.get("peer", "")
        length = hello.get("length", "")
        if role not in allowed_roles or not isinstance(client_id, str) or not client_id or len(client_id) > 128:
            await send_json(writer, {"ok": False, "error": "invalid_auth_hello"})
            return None
        if not isinstance(public_key, str) or not valid_endpoint_public_key(public_key):
            await send_json(writer, {"ok": False, "error": "invalid_auth_hello"})
            return None
        known = self.state.clients.get(client_id)
        if known is None and (not self.config.enrollment_enabled or not allow_enrollment or role not in {"control", "relay"}):
            await send_json(writer, {"ok": False, "error": "unknown_endpoint"})
            return None
        if known is not None and known.get("public_key") != public_key:
            await send_json(writer, {"ok": False, "error": "endpoint_key_changed"})
            return None
        challenge = secrets.token_urlsafe(32)
        key = secrets.token_urlsafe(24)
        self.auth_challenges[key] = (client_id, public_key, challenge, client_kind, time.monotonic() + 60)
        await send_json(writer, {"type": "auth_challenge", "challenge": challenge})
        proof = json.loads(await asyncio.wait_for(reader.readline(), timeout=15))
        record = self.auth_challenges.pop(key, None)
        signature = proof.get("signature")
        if record is None or proof.get("type") != "auth_proof" or not isinstance(signature, str):
            await send_json(writer, {"ok": False, "error": "invalid_auth_proof"})
            return None
        enrolled_id, enrolled_key, enrolled_expected, enrolled_kind, expires = record
        transcript = f"wisp-relay-auth-v1\n{role}\n{client_id}\n{enrolled_expected}\n{ticket}\n{peer}\n{length}".encode("ascii")
        try:
            decoded_key = base64.urlsafe_b64decode(enrolled_key + "=" * (-len(enrolled_key) % 4))
            public = serialization.load_der_public_key(decoded_key)
            decoded_signature = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
            if expires < time.monotonic():
                raise ValueError("expired challenge")
            public.verify(decoded_signature, transcript, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
        except Exception:
            await send_json(writer, {"ok": False, "error": "invalid_auth_proof"})
            return None
        if known is None:
            access = self.state.enroll_client(enrolled_id, enrolled_key, client_kind=enrolled_kind)
        else:
            access = self.state.client_access(enrolled_id, enrolled_key)
        if access not in {"approved", "admin"} and not (access == "pending" and allow_pending_control and role == "control"):
            await send_json(writer, {"ok": False, "error": "endpoint_" + access if access in {"pending", "rejected", "revoked"} else access})
            return None
        self.state.register_client(enrolled_id, enrolled_key, replace=False)
        self.state.clients[enrolled_id]["client_kind"] = enrolled_kind
        self.state.save()
        await send_json(writer, {"ok": True, "type": "authenticated", "client_id": enrolled_id})
        return enrolled_id

    async def handle_bulk(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        connection: _BulkConnection | None = None
        try:
            header = json.loads(await asyncio.wait_for(reader.readline(), timeout=15))
            if (
                header.get("type") != "bulk_connect"
                or header.get("role") not in {"sender", "receiver"}
                or not all(isinstance(header.get(key), str) and header.get(key) for key in ("session_id", "transfer_id", "sender", "recipient"))
                or header.get("sender") == header.get("recipient")
                or not isinstance(header.get("length"), int)
                or isinstance(header.get("length"), bool)
                or not 16 <= header["length"] <= self.MAX_BULK_BYTES
            ):
                await send_json(writer, {"ok": False, "error": "invalid_bulk_connect"})
                return
            key = f'{header["session_id"]}:{header["transfer_id"]}'
            LOG.info(
                "bulk_connect role=%s session_id=%s transfer_id=%s sender=%s recipient=%s length=%s",
                header["role"], header["session_id"], header["transfer_id"],
                header["sender"], header["recipient"], header["length"],
            )
            connection = _BulkConnection(
                header["sender"], header["recipient"], header["role"], header["length"], reader, writer,
            )
            async with self.bulk_lock:
                now = time.monotonic()
                self.consumed_bulk = {
                    used_ticket: expires for used_ticket, expires in self.consumed_bulk.items() if expires > now
                }
                if key in self.consumed_bulk:
                    await send_json(writer, {"ok": False, "error": "bulk_transfer_used"})
                    return
                waiting = self.pending_bulk.pop(key, None)
                if waiting is None:
                    if len(self.pending_bulk) >= self.MAX_PENDING_BULK:
                        await send_json(writer, {"ok": False, "error": "too_many_pending_bulk_offers"})
                        return
                    self.pending_bulk[key] = connection
                elif (
                    waiting.role == connection.role
                    or waiting.client_id != connection.peer
                    or waiting.peer != connection.client_id
                    or waiting.length != connection.length
                ):
                    self.pending_bulk[key] = waiting
                    await send_json(writer, {"ok": False, "error": "bulk_pair_mismatch"})
                    return
                else:
                    self.consumed_bulk[key] = now + self.BULK_TICKET_TTL_SECONDS
                    sender = connection if connection.role == "sender" else waiting
                    receiver = connection if connection.role == "receiver" else waiting
                    task = asyncio.create_task(self._pipe_bulk(sender, receiver))
                    connection.task = task
                    waiting.task = task
            if connection.task is None:
                await asyncio.wait_for(connection.paired.wait(), timeout=30)
            assert connection.task is not None
            await connection.task
        except (asyncio.TimeoutError, ConnectionError, asyncio.IncompleteReadError, json.JSONDecodeError, OSError):
            pass
        finally:
            if connection is not None:
                async with self.bulk_lock:
                    for key, waiting in list(self.pending_bulk.items()):
                        if waiting is connection:
                            self.pending_bulk.pop(key, None)
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    async def _pipe_bulk(self, sender: "_BulkConnection", receiver: "_BulkConnection") -> None:
        sender.paired.set()
        receiver.paired.set()
        await send_json(sender.writer, {"ok": True, "type": "bulk_ready"})
        await send_json(receiver.writer, {"ok": True, "type": "bulk_ready"})
        await asyncio.wait_for(
            self._copy_bulk_ciphertext(sender, receiver),
            timeout=self.BULK_IO_TIMEOUT_SECONDS,
        )
        await send_json(sender.writer, {"ok": True, "type": "bulk_complete"})
        await send_json(receiver.writer, {"ok": True, "type": "bulk_complete"})

    @staticmethod
    async def _copy_bulk_ciphertext(sender: "_BulkConnection", receiver: "_BulkConnection") -> None:
        remaining = sender.length
        while remaining:
            chunk = await sender.reader.readexactly(min(256 * 1024, remaining))
            receiver.writer.write(chunk)
            await receiver.writer.drain()
            remaining -= len(chunk)

    async def forward(self, sender: str, envelope: dict[str, Any]) -> None:
        recipient = envelope.get("recipient")
        if envelope.get("type") == "session_envelope":
            required = {"version", "type", "session_id", "sender", "recipient", "sequence", "ciphertext"}
            allowed = required
            valid_shape = (
                envelope.get("version") == 1
                and isinstance(envelope.get("session_id"), str) and bool(envelope.get("session_id"))
                and isinstance(envelope.get("sequence"), int) and not isinstance(envelope.get("sequence"), bool)
                and envelope.get("sequence") >= 0
                and envelope.get("sequence") < (1 << 64)
                and isinstance(envelope.get("ciphertext"), str)
                and 0 < len(envelope.get("ciphertext")) <= 1024 * 1024
            )
        elif envelope.get("type") == "session_reset":
            required = {"type", "sender", "recipient", "reason"}
            allowed = required
            valid_shape = (
                isinstance(envelope.get("reason"), str)
                and 1 <= len(envelope.get("reason")) <= 128
            )
        else:
            required = {"version", "type", "sender", "recipient", "message_id", "algorithm", "encrypted_key", "nonce", "ciphertext", "signature"}
            allowed = required | {"sender_public_key"}
            valid_shape = envelope.get("type") == "envelope"

        sender_matches_transport = envelope.get("sender") == sender
        if envelope.get("type") == "session_reset":
            valid_shape = valid_shape and sender_matches_transport
        if (
            not recipient
            or not sender_matches_transport
            or not valid_shape
            or not set(envelope).issubset(allowed)
            or not required.issubset(envelope)
        ):
            session = self.sessions.get(sender)
            if session:
                await send_json(session[1], {"ok": False, "error": "invalid_envelope"})
            return
        destination = self.sessions.get(recipient)
        source = self.sessions.get(sender)
        if destination:
            # The sender's transport is request/response oriented: it expects
            # the relay acceptance before the recipient's application reply.
            # Send this first so a fast Wisp response cannot race it.
            if source:
                if envelope.get("type") == "session_envelope":
                    await send_json(source[1], {
                        "ok": True, "type": "accepted", "session_id": envelope.get("session_id"),
                        "sequence": envelope.get("sequence"),
                    })
                elif envelope.get("type") == "session_reset":
                    await send_json(source[1], {"ok": True, "type": "accepted", "message_type": "session_reset"})
                else:
                    await send_json(source[1], {"ok": True, "type": "accepted", "message_id": envelope.get("message_id")})
            try:
                await send_json(destination[1], envelope)
            except (ConnectionError, OSError) as exc:
                LOG.info("relay destination disconnected while forwarding %s -> %s: %s", sender, recipient, exc)
                if self.sessions.get(recipient, (None, None))[1] is destination[1]:
                    self.sessions.pop(recipient, None)
                    self.relay_liveness.pop(recipient, None)
                    await self.broadcast_catalog()
                destination[1].close()
                try:
                    await destination[1].wait_closed()
                except (ConnectionError, OSError):
                    pass
        else:
            if source:
                await send_json(source[1], {"ok": False, "error": "recipient_offline"})


async def send_json(writer: asyncio.StreamWriter, value: dict[str, Any]) -> None:
    writer.write(json.dumps(value, separators=(",", ":")).encode() + b"\n")
    await writer.drain()


@dataclass
class _BulkConnection:
    client_id: str
    peer: str
    role: str
    length: int
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    paired: asyncio.Event = field(default_factory=asyncio.Event)
    task: asyncio.Task[None] | None = None


async def serve(
    runtime: RelayRuntime,
    control_host: str,
    control_port: int,
    relay_host: str,
    relay_port: int,
    bulk_host: str = "0.0.0.0",
    bulk_port: int = 4444,
    tls_cert_path: str | Path | None = None,
    tls_key_path: str | Path | None = None,
) -> None:
    if tls_cert_path is None or tls_key_path is None:
        raise ValueError("production relay listeners require TLS certificate and key")
    tls_context = create_server_ssl_context(tls_cert_path, tls_key_path)
    runtime.certificate_der = x509.load_pem_x509_certificate(Path(tls_cert_path).read_bytes()).public_bytes(serialization.Encoding.DER)
    control = await asyncio.start_server(runtime.handle_control, control_host, control_port, ssl=tls_context)
    relay = await asyncio.start_server(
        runtime.handle_relay,
        relay_host,
        relay_port,
        limit=runtime.RELAY_LINE_LIMIT_BYTES,
        ssl=tls_context,
    )
    bulk = await asyncio.start_server(runtime.handle_bulk, bulk_host, bulk_port, ssl=tls_context)
    LOG.info("control listening on %s:%s", control_host, control_port)
    LOG.info("relay listening on %s:%s", relay_host, relay_port)
    LOG.info("bulk listening on %s:%s", bulk_host, bulk_port)
    async with control, relay, bulk:
        await asyncio.gather(control.serve_forever(), relay.serve_forever(), bulk.serve_forever())
