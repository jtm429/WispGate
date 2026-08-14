from __future__ import annotations

import asyncio
import base64
import hmac
import json
import logging
import secrets
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .core import RelayConfig, RelayState, parse_bootstrap

LOG = logging.getLogger("appserve.relay")


@dataclass
class RelayRuntime:
    config: RelayConfig
    state: RelayState
    sessions: dict[str, tuple[str, asyncio.StreamWriter]] = field(default_factory=dict)
    control_sessions: dict[str, tuple[str, asyncio.StreamWriter]] = field(default_factory=dict)
    update_token: str | None = None
    update_command: tuple[str, ...] | None = None

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
            self.state.register_client(client_id, client_key)
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
                    "wisps": list(self.state.wisps.values()),
                },
            )
            registration = await asyncio.wait_for(reader.readline(), timeout=2)
            if registration:
                message = json.loads(registration)
                if message.get("type") == "wisps":
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
                    await send_json(writer, {"ok": True, "type": "wisps_registered", "items": list(self.state.wisps.values())})
                    await self.broadcast_catalog()
                    if client_id == "android-user":
                        self.control_sessions[client_id] = (token, writer)
                        while await reader.readline():
                            pass
                elif message.get("type") == "update_server":
                    await self.handle_update_request(writer, message)
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
        message = {"ok": True, "type": "catalog_update", "items": list(self.state.wisps.values())}
        stale: list[str] = []
        for client_id, (_, writer) in list(self.control_sessions.items()):
            try:
                await send_json(writer, message)
            except (ConnectionError, OSError):
                stale.append(client_id)
        for client_id in stale:
            self.control_sessions.pop(client_id, None)

    async def handle_update_request(self, writer: asyncio.StreamWriter, message: dict[str, Any]) -> None:
        supplied = message.get("token", "")
        if not self.update_token or not hmac.compare_digest(supplied, self.update_token):
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
                if message.get("type") != "envelope":
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

    async def forward(self, sender: str, envelope: dict[str, Any]) -> None:
        recipient = envelope.get("recipient")
        if not recipient or envelope.get("sender") != sender or "ciphertext" not in envelope:
            session = self.sessions.get(sender)
            if session:
                await send_json(session[1], {"ok": False, "error": "invalid_envelope"})
            return
        destination = self.sessions.get(recipient)
        if destination:
            await send_json(destination[1], envelope)
        else:
            body = envelope.get("body", {})
            if body.get("action") in {"state_request", "user_action"}:
                source = self.sessions.get(sender)
                if source:
                    await send_json(source[1], {"ok": False, "error": "recipient_offline"})
                return
            self.state.queue(recipient, envelope)
            self.state.save()
        source = self.sessions.get(sender)
        if source:
            await send_json(source[1], {"ok": True, "type": "accepted", "message_id": envelope.get("message_id")})


async def send_json(writer: asyncio.StreamWriter, value: dict[str, Any]) -> None:
    writer.write(json.dumps(value, separators=(",", ":")).encode() + b"\n")
    await writer.drain()


async def serve(runtime: RelayRuntime, control_host: str, control_port: int, relay_host: str, relay_port: int) -> None:
    control = await asyncio.start_server(runtime.handle_control, control_host, control_port)
    relay = await asyncio.start_server(runtime.handle_relay, relay_host, relay_port)
    LOG.info("control listening on %s:%s", control_host, control_port)
    LOG.info("relay listening on %s:%s", relay_host, relay_port)
    async with control, relay:
        await asyncio.gather(control.serve_forever(), relay.serve_forever())
