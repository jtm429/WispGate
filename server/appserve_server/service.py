from __future__ import annotations

import asyncio
import base64
import json
import logging
import secrets
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .core import RelayConfig, RelayState, parse_bootstrap

LOG = logging.getLogger("appserve.relay")


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
    control_sessions: dict[str, tuple[str, asyncio.StreamWriter]] = field(default_factory=dict)
    update_command: tuple[str, ...] | None = None
    pending_bulk: dict[str, "_BulkConnection"] = field(default_factory=dict)
    consumed_bulk: dict[str, float] = field(default_factory=dict)
    bulk_lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    MAX_BULK_BYTES = 256 * 1024 * 1024 + 16
    MAX_PENDING_BULK = 128
    BULK_TICKET_TTL_SECONDS = 10 * 60
    BULK_IO_TIMEOUT_SECONDS = 10 * 60

    def catalog_items(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for manifest in self.state.wisps.values():
            owner = manifest.get("owner")
            public_key = self.state.clients.get(owner, {}).get("public_key")
            if not public_key or not valid_endpoint_public_key(public_key):
                continue
            items.append({**manifest, "public_key": public_key})
        return items

    async def handle_control(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=15)
            request = json.loads(line)
            if request.get("type") != "join":
                await send_json(writer, {"ok": False, "error": "invalid_bootstrap"})
                return
            payload = parse_bootstrap(self.config, request["payload"].encode("ascii"))
            client_id = payload["client_id"]
            client_key = payload["client_public_key"]
            self.state.register_client(client_id, client_key, replace=False)
            token = secrets.token_urlsafe(32)
            self.state.clients[client_id]["session_token"] = token
            self.state.save()
            await send_json(
                writer,
                {
                    "ok": True,
                    "type": "joined",
                    "client_id": client_id,
                    "session_token": token,
                    "queued": len(self.state.queues.get(client_id, [])),
                    "wisps": self.catalog_items(),
                },
            )
            registration = await asyncio.wait_for(reader.readline(), timeout=2)
            if registration:
                message = json.loads(registration)
                if message.get("type") == "wisps":
                    if message.get("client_public_key"):
                        self.state.register_client(client_id, message["client_public_key"])
                    self.state.remove_wisps_for_owner(client_id)
                    for item in message.get("items", []):
                        if item.get("id"):
                            self.state.wisps[item["id"]] = {
                                "id": item["id"],
                                "name": item.get("name", item["id"]),
                                "description": item.get("description", ""),
                                "owner": client_id,
                            }
                    self.state.save()
                    await send_json(writer, {"ok": True, "type": "wisps_registered", "items": self.catalog_items()})
                    await self.broadcast_catalog()
                    if client_id == "android-user":
                        self.control_sessions[client_id] = (token, writer)
                        while await reader.readline():
                            pass
                elif message.get("type") == "update_server":
                    await self.handle_update_request(writer, client_id)
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
        stale: list[str] = []
        for client_id, (_, writer) in list(self.control_sessions.items()):
            try:
                await send_json(writer, message)
            except (ConnectionError, OSError):
                stale.append(client_id)
        for client_id in stale:
            self.control_sessions.pop(client_id, None)

    async def handle_update_request(self, writer: asyncio.StreamWriter, client_id: str) -> None:
        if client_id != "android-user":
            await send_json(writer, {"ok": False, "error": "update_unauthorized"})
            return
        if not self.update_command:
            await send_json(writer, {"ok": False, "error": "update_unconfigured"})
            return
        await send_json(writer, {"ok": True, "type": "update_started"})
        subprocess.Popen(self.update_command, start_new_session=True)

    async def handle_relay(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        client_id = None
        try:
            hello = json.loads(await asyncio.wait_for(reader.readline(), timeout=15))
            if hello.get("type") != "session":
                await send_json(writer, {"ok": False, "error": "unauthenticated"})
                return
            token = hello.get("session_token")
            client_id = next(
                (cid for cid, record in self.state.clients.items() if record.get("session_token") == token),
                None,
            )
            if not client_id:
                await send_json(writer, {"ok": False, "error": "unauthenticated"})
                return
            self.sessions[client_id] = (token, writer)
            self.state.clients[client_id]["last_seen"] = int(asyncio.get_running_loop().time())
            await send_json(writer, {"ok": True, "type": "ready", "client_id": client_id})
            for queued in self.state.drain(client_id):
                await send_json(writer, queued)
            self.state.save()
            LOG.info("relay connected: %s from %s", client_id, peer)
            while line := await reader.readline():
                message = json.loads(line)
                if message.get("type") not in {"envelope", "session_envelope"}:
                    await send_json(writer, {"ok": False, "error": "invalid_envelope"})
                    continue
                await self.forward(client_id, message)
        except (asyncio.TimeoutError, ConnectionError, json.JSONDecodeError) as exc:
            LOG.info("relay connection ended for %s: %s", client_id or peer, exc)
        finally:
            if client_id and self.sessions.get(client_id, (None, None))[1] is writer:
                self.sessions.pop(client_id, None)
                self.state.remove_wisps_for_owner(client_id)
                self.state.save()
                await self.broadcast_catalog()
            writer.close()
            await writer.wait_closed()

    async def handle_bulk(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        connection: _BulkConnection | None = None
        try:
            header = json.loads(await asyncio.wait_for(reader.readline(), timeout=15))
            token = header.get("session_token")
            client_id = next(
                (cid for cid, record in self.state.clients.items() if record.get("session_token") == token),
                None,
            )
            if not client_id:
                await send_json(writer, {"ok": False, "error": "unauthenticated"})
                return
            ticket = header.get("ticket")
            role = header.get("role")
            peer = header.get("peer")
            length = header.get("length")
            if (
                header.get("type") != "bulk"
                or not isinstance(ticket, str) or not 16 <= len(ticket) <= 256
                or role not in {"sender", "receiver"}
                or not isinstance(peer, str) or not peer or peer == client_id
                or not isinstance(length, int) or isinstance(length, bool)
                or not 16 <= length <= self.MAX_BULK_BYTES
            ):
                await send_json(writer, {"ok": False, "error": "invalid_bulk_offer"})
                return
            connection = _BulkConnection(client_id, peer, role, length, reader, writer)
            async with self.bulk_lock:
                now = time.monotonic()
                self.consumed_bulk = {
                    used_ticket: expires
                    for used_ticket, expires in self.consumed_bulk.items()
                    if expires > now
                }
                if ticket in self.consumed_bulk:
                    await send_json(writer, {"ok": False, "error": "bulk_ticket_used"})
                    return
                waiting = self.pending_bulk.pop(ticket, None)
                if waiting is None:
                    if len(self.pending_bulk) >= self.MAX_PENDING_BULK:
                        await send_json(writer, {"ok": False, "error": "too_many_pending_bulk_offers"})
                        return
                    self.pending_bulk[ticket] = connection
                elif (
                    waiting.role == role
                    or waiting.client_id != peer
                    or waiting.peer != client_id
                    or waiting.length != length
                ):
                    self.pending_bulk[ticket] = waiting
                    await send_json(writer, {"ok": False, "error": "bulk_pair_mismatch"})
                    return
                else:
                    self.consumed_bulk[ticket] = now + self.BULK_TICKET_TTL_SECONDS
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
                    for ticket, waiting in list(self.pending_bulk.items()):
                        if waiting is connection:
                            self.pending_bulk.pop(ticket, None)
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
        else:
            required = {"version", "type", "sender", "recipient", "message_id", "algorithm", "encrypted_key", "nonce", "ciphertext", "signature"}
            allowed = required | {"sender_public_key"}
            valid_shape = envelope.get("type") == "envelope"

        if (
            not recipient
            or envelope.get("sender") != sender
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
                else:
                    await send_json(source[1], {"ok": True, "type": "accepted", "message_id": envelope.get("message_id")})
            try:
                await send_json(destination[1], envelope)
            except (ConnectionError, OSError) as exc:
                LOG.info("relay destination disconnected while forwarding %s -> %s: %s", sender, recipient, exc)
                if self.sessions.get(recipient, (None, None))[1] is destination[1]:
                    self.sessions.pop(recipient, None)
                    self.state.remove_wisps_for_owner(recipient)
                    self.state.save()
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
) -> None:
    control = await asyncio.start_server(runtime.handle_control, control_host, control_port)
    relay = await asyncio.start_server(runtime.handle_relay, relay_host, relay_port)
    bulk = await asyncio.start_server(runtime.handle_bulk, bulk_host, bulk_port)
    LOG.info("control listening on %s:%s", control_host, control_port)
    LOG.info("relay listening on %s:%s", relay_host, relay_port)
    LOG.info("bulk listening on %s:%s", bulk_host, bulk_port)
    async with control, relay, bulk:
        await asyncio.gather(control.serve_forever(), relay.serve_forever(), bulk.serve_forever())
