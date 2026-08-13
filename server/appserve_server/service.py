from __future__ import annotations

import asyncio
import base64
import json
import logging
import secrets
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

    async def handle_control(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=15)
            request = json.loads(line)
            if request.get("type") != "join":
                await send_json(writer, {"ok": False, "error": "invalid_bootstrap"})
                return
            payload = parse_bootstrap(self.config, base64.urlsafe_b64decode(request["payload"]))
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
                },
            )
            LOG.info("client joined: %s from %s", client_id, peer)
        except (KeyError, ValueError, json.JSONDecodeError, base64.binascii.Error) as exc:
            LOG.warning("rejected join from %s: %s", peer, exc)
            await send_json(writer, {"ok": False, "error": "invalid_bootstrap"})
        finally:
            writer.close()
            await writer.wait_closed()

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
