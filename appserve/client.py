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

from .e2e import (
    decrypt_envelope,
    encrypt_envelope,
    generate_identity,
    load_or_create_identity,
    public_key_text,
)


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
    def __init__(self, info: ServerInfo, client_id: str, *, identity_key=None, peer_store_path: str | Path | None = None):
        self.info = info
        self.client_id = client_id
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._session_token: str | None = None
        self._wisps: dict[str, Wisp] = {}
        self._identity_key = identity_key or generate_identity()
        self._peer_store_path = Path(peer_store_path) if peer_store_path else None
        self._peer_keys: dict[str, str] = {}
        if self._peer_store_path and self._peer_store_path.exists():
            stored = json.loads(self._peer_store_path.read_text(encoding="utf-8"))
            if isinstance(stored, dict):
                self._peer_keys = {str(key): str(value) for key, value in stored.items()}

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
            await self._send(writer, self._registration_message())
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
            await self._handle_envelope(message)

    def peer_public_key(self, client_id: str) -> str | None:
        return self._peer_keys.get(client_id)

    def _registration_message(self) -> dict[str, Any]:
        return {
            "type": "wisps",
            "client_public_key": public_key_text(self._identity_key),
            "items": [w.manifest() for w in self._wisps.values()],
        }

    def _remember_peer(self, client_id: str, public_key: str) -> None:
        known = self._peer_keys.get(client_id)
        if known and known != public_key:
            raise ValueError(f"peer public key changed for {client_id}")
        if known:
            return
        self._peer_keys[client_id] = public_key
        if self._peer_store_path:
            self._peer_store_path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self._peer_store_path.with_suffix(self._peer_store_path.suffix + ".tmp")
            temporary.write_text(json.dumps(self._peer_keys, sort_keys=True), encoding="utf-8")
            temporary.replace(self._peer_store_path)

    async def _handle_envelope(self, message: dict[str, Any]) -> None:
        sender = message["sender"]
        body, sender_key = decrypt_envelope(message, self._identity_key, self._peer_keys.get(sender))
        self._remember_peer(sender, sender_key)
        wisp = self._wisps.get(body.get("wisp_id"))
        if not wisp:
            return
        if body.get("action") == "state_request":
            state = wisp.state()
        else:
            result = wisp.action(body.get("action_data", {}))
            state = await result if asyncio.iscoroutine(result) else result
        await self._send_envelope(sender, {"wisp_id": wisp.id, "response": state})

    async def _send_envelope(self, recipient: str, body: dict[str, Any]) -> None:
        assert self._writer is not None
        recipient_key = self._peer_keys.get(recipient)
        if not recipient_key:
            raise ValueError(f"no trusted public key for {recipient}")
        await self._send(
            self._writer,
            encrypt_envelope(
                sender=self.client_id,
                recipient=recipient,
                message_id=secrets.token_urlsafe(16),
                body=body,
                recipient_public_key=recipient_key,
                sender_private_key=self._identity_key,
            ),
        )

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
    config_path = Path(path)
    data = json.loads(config_path.read_text(encoding="utf-8"))
    key = data["server_public_key"]
    client_id = data.get("client_id", "python-wisp")
    identity_path = config_path.with_name(f".{config_path.stem}-{client_id}-identity.pem")
    peers_path = config_path.with_name(f".{config_path.stem}-{client_id}-peers.json")
    return AppserveClient(
        ServerInfo(
            host=data["server"],
            control_port=int(data.get("control_port", data.get("port", 443))),
            relay_port=int(data.get("relay_port", 4443)),
            server_public_key=base64.urlsafe_b64decode(key),
            deployment_id=data.get("deployment_id", "private"),
        ),
        client_id=client_id,
        identity_key=load_or_create_identity(identity_path),
        peer_store_path=peers_path,
    )
