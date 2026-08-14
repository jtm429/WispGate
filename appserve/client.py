from __future__ import annotations

import asyncio
import base64
import json
import logging
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class ServerInfo:
    host: str
    control_port: int
    relay_port: int
    server_public_key: bytes
    deployment_id: str = "private"


@dataclass
class Wisp:
    id: str
    name: str
    description: str
    state: Callable[[], dict[str, Any]]
    action: Callable[[dict[str, Any]], Awaitable[dict[str, Any]] | dict[str, Any]]

    def manifest(self) -> dict[str, str]:
        return {"id": self.id, "name": self.name, "description": self.description}


class AppserveClient:
    def __init__(self, info: ServerInfo, client_id: str):
        self.info = info
        self.client_id = client_id
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._session_token: str | None = None
        self._wisps: dict[str, Wisp] = {}

    def register(self, wisp: Wisp) -> None:
        self._wisps[wisp.id] = wisp

    async def serve(self) -> None:
        delay = 1.0
        try:
            while True:
                try:
                    await self._serve_once()
                    delay = 1.0
                    raise ConnectionError("relay connection closed")
                except asyncio.CancelledError:
                    raise
                except (ConnectionError, OSError, asyncio.IncompleteReadError, json.JSONDecodeError) as cause:
                    self._close_connection()
                    LOG.warning("relay connection lost: %s; reconnecting in %.1fs", cause, delay)
                    await asyncio.sleep(delay)
                    delay = min(delay * 2, 30.0)
        finally:
            await self.close()

    async def _serve_once(self) -> None:
        reader, writer = await asyncio.open_connection(self.info.host, self.info.control_port)
        self._reader, self._writer = reader, writer
        try:
            bootstrap = self._bootstrap_payload()
            await self._send(writer, {"type": "join", "payload": bootstrap})
            joined = await self._read(reader)
            if not joined.get("ok"):
                raise ConnectionError(joined.get("error", "join failed"))
            self._session_token = joined["session_token"]
            await self._send(writer, {"type": "wisps", "items": [w.manifest() for w in self._wisps.values()]})
        finally:
            writer.close()
            await writer.wait_closed()
            self._reader = self._writer = None

        reader, writer = await asyncio.open_connection(self.info.host, self.info.relay_port)
        self._reader, self._writer = reader, writer
        await self._send(writer, {"type": "session", "session_token": self._session_token})
        ready = await self._read(reader)
        if not ready.get("ok"):
            raise ConnectionError(ready.get("error", "session failed"))
        await self._event_loop()

    async def close(self) -> None:
        writer = self._writer
        self._reader = self._writer = None
        self._session_token = None
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    def _close_connection(self) -> None:
        if self._writer is not None:
            self._writer.close()
        self._reader = self._writer = None
        self._session_token = None

    async def _event_loop(self) -> None:
        assert self._reader is not None
        while line := await self._reader.readline():
            message = json.loads(line)
            if message.get("type") != "envelope":
                continue
            body = message.get("body", {})
            wisp = self._wisps.get(body.get("wisp_id"))
            if not wisp:
                continue
            if body.get("action") == "state_request":
                state = wisp.state()
            else:
                result = wisp.action(body.get("action_data", {}))
                state = await result if asyncio.iscoroutine(result) else result
            await self._send_envelope(message["sender"], {"wisp_id": wisp.id, "response": state})

    async def _send_envelope(self, recipient: str, body: dict[str, Any]) -> None:
        assert self._writer is not None
        await self._send(self._writer, {
            "type": "envelope",
            "sender": self.client_id,
            "recipient": recipient,
            "message_id": secrets.token_urlsafe(16),
            "ciphertext": "appserve-v1",
            "body": body,
        })

    def _bootstrap_payload(self) -> str:
        key = serialization.load_der_public_key(self.info.server_public_key)
        payload = json.dumps({
            "deployment_id": self.info.deployment_id,
            "client_id": self.client_id,
            "client_public_key": self.client_id,
            "nonce": secrets.token_urlsafe(20),
            "timestamp": int(time.time()),
        }, separators=(",", ":")).encode()
        encrypted = key.encrypt(
            payload,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )
        return base64.urlsafe_b64encode(encrypted).decode()

    @staticmethod
    async def _send(writer: asyncio.StreamWriter, value: dict[str, Any]) -> None:
        writer.write(json.dumps(value, separators=(",", ":")).encode() + b"\n")
        await writer.drain()

    @staticmethod
    async def _read(reader: asyncio.StreamReader) -> dict[str, Any]:
        return json.loads(await reader.readline())


def load(path: str | Path) -> AppserveClient:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    key = data["server_public_key"]
    return AppserveClient(
        ServerInfo(
            host=data["server"],
            control_port=int(data.get("control_port", data.get("port", 443))),
            relay_port=int(data.get("relay_port", 4443)),
            server_public_key=base64.urlsafe_b64decode(key),
            deployment_id=data.get("deployment_id", "private"),
        ),
        client_id=data.get("client_id", "python-wisp"),
    )
