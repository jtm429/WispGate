from __future__ import annotations

import asyncio
import base64
import json
import logging
import secrets
import shutil
import tempfile
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


@dataclass(frozen=True)
class UploadedFile:
    field: str
    name: str
    content_type: str
    size: int
    path: Path

    def open(self, mode: str = "rb"):
        return self.path.open(mode)

    def read_bytes(self) -> bytes:
        return self.path.read_bytes()

    def save(self, destination: str | Path) -> Path:
        target = Path(destination)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.path, target)
        return target


class WispAction(dict[str, Any]):
    def __init__(self, values: dict[str, Any], files: dict[str, UploadedFile | tuple[UploadedFile, ...]] | None = None):
        super().__init__(values)
        self.files = files or {}


@dataclass
class _IncomingFile:
    id: str
    field: str
    name: str
    content_type: str
    size: int
    path: Path
    received: int = 0


@dataclass
class _IncomingTransfer:
    sender: str
    wisp: Wisp
    action_data: dict[str, Any]
    directory: Path
    files: dict[str, _IncomingFile]
    created_at: float


class AppserveClient:
    FILE_CHUNK_BYTES = 24 * 1024
    MAX_FILES_PER_ACTION = 32
    MAX_FILE_ACTION_BYTES = 256 * 1024 * 1024
    MAX_ACTIVE_TRANSFERS_PER_SENDER = 4
    FILE_TRANSFER_TIMEOUT_SECONDS = 10 * 60

    def __init__(
        self,
        info: ServerInfo,
        client_id: str,
        *,
        identity_key=None,
        peer_store_path: str | Path | None = None,
        transfer_directory: str | Path | None = None,
    ):
        self.info = info
        self.client_id = client_id
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._session_token: str | None = None
        self._wisps: dict[str, Wisp] = {}
        self._identity_key = identity_key or generate_identity()
        self._peer_store_path = Path(peer_store_path) if peer_store_path else None
        self._transfer_directory = Path(transfer_directory) if transfer_directory else Path(tempfile.gettempdir()) / "wispgate-transfers"
        self._transfers: dict[tuple[str, str], _IncomingTransfer] = {}
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
        for transfer in list(self._transfers.values()):
            self._cleanup_transfer(transfer)
        self._transfers.clear()

    def _close_connection(self) -> None:
        if self._writer is not None:
            self._writer.close()
        self._reader = self._writer = None
        self._session_token = None
        for transfer in list(self._transfers.values()):
            self._cleanup_transfer(transfer)
        self._transfers.clear()

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
        self._expire_file_transfers()
        wisp = self._wisps.get(body.get("wisp_id"))
        if not wisp:
            return
        action_kind = body.get("action")
        if action_kind == "state_request":
            state = wisp.state()
            response = {"wisp_id": wisp.id, "response": state}
        elif action_kind in {"file_begin", "file_chunk", "file_commit"}:
            transfer_id = str(body.get("transfer_id", ""))
            try:
                if action_kind == "file_begin":
                    response = self._begin_file_action(sender, wisp, body)
                elif action_kind == "file_chunk":
                    response = self._accept_file_chunk(sender, wisp, body)
                else:
                    response = await self._commit_file_action(sender, wisp, body)
            except (KeyError, TypeError, ValueError) as cause:
                transfer = self._transfers.pop((sender, transfer_id), None)
                if transfer is not None:
                    self._cleanup_transfer(transfer)
                response = self._transfer_response(wisp, {
                    "type": "error",
                    "transfer_id": transfer_id,
                    "error": str(cause),
                })
        else:
            result = wisp.action(WispAction(body.get("action_data", {})))
            state = await result if asyncio.iscoroutine(result) else result
            response = {"wisp_id": wisp.id, "response": state}
        await self._send_envelope(sender, response)

    def _transfer_response(self, wisp: Wisp, transfer: dict[str, Any]) -> dict[str, Any]:
        return {"wisp_id": wisp.id, "transfer": transfer}

    def _begin_file_action(self, sender: str, wisp: Wisp, body: dict[str, Any]) -> dict[str, Any]:
        transfer_id = str(body.get("transfer_id", ""))
        manifests = body.get("files")
        action_data = body.get("action_data", {})
        if not transfer_id or not isinstance(manifests, list) or not manifests:
            raise ValueError("file action requires a transfer id and at least one file")
        if not isinstance(action_data, dict):
            raise ValueError("file action data must be an object")
        if len(manifests) > self.MAX_FILES_PER_ACTION:
            raise ValueError("too many files in one action")
        key = (sender, transfer_id)
        if key in self._transfers:
            raise ValueError("transfer id is already active")
        active_for_sender = sum(1 for transfer_sender, _ in self._transfers if transfer_sender == sender)
        if active_for_sender >= self.MAX_ACTIVE_TRANSFERS_PER_SENDER:
            raise ValueError("too many active file transfers")

        self._transfer_directory.mkdir(parents=True, exist_ok=True)
        directory = Path(tempfile.mkdtemp(prefix="transfer-", dir=self._transfer_directory))
        files: dict[str, _IncomingFile] = {}
        total = 0
        reserved = sum(file.size for transfer in self._transfers.values() for file in transfer.files.values())
        try:
            for index, manifest in enumerate(manifests):
                if not isinstance(manifest, dict):
                    raise ValueError("invalid file manifest")
                file_id = str(manifest.get("id", ""))
                field = str(manifest.get("field", ""))
                name = str(manifest.get("name", ""))
                content_type = str(manifest.get("content_type", "application/octet-stream"))
                size = manifest.get("size")
                if (
                    not file_id or len(file_id) > 128 or file_id in files
                    or not field or len(field) > 128
                    or not name or len(name) > 512
                    or len(content_type) > 128
                    or not isinstance(size, int) or isinstance(size, bool) or size < 0
                ):
                    raise ValueError("invalid file manifest")
                total += size
                if reserved + total > self.MAX_FILE_ACTION_BYTES:
                    raise ValueError("file action exceeds the configured size limit")
                path = directory / f"{index}.upload"
                path.touch()
                files[file_id] = _IncomingFile(file_id, field, name, content_type, size, path)
        except Exception:
            shutil.rmtree(directory, ignore_errors=True)
            raise

        self._transfers[key] = _IncomingTransfer(sender, wisp, dict(action_data), directory, files, time.monotonic())
        return self._transfer_response(wisp, {
            "type": "ready",
            "transfer_id": transfer_id,
            "chunk_size": self.FILE_CHUNK_BYTES,
        })

    def _accept_file_chunk(self, sender: str, wisp: Wisp, body: dict[str, Any]) -> dict[str, Any]:
        transfer_id = str(body.get("transfer_id", ""))
        transfer = self._transfers.get((sender, transfer_id))
        if transfer is None or transfer.wisp.id != wisp.id:
            raise ValueError("unknown file transfer")
        file_id = str(body.get("file_id", ""))
        incoming = transfer.files.get(file_id)
        if incoming is None:
            raise ValueError("unknown file in transfer")
        offset = body.get("offset")
        if offset != incoming.received:
            raise ValueError(f"unexpected file offset; expected {incoming.received}")
        encoded = body.get("data")
        if not isinstance(encoded, str):
            raise ValueError("file chunk data must be base64url text")
        try:
            chunk = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
        except Exception as cause:
            raise ValueError("invalid file chunk encoding") from cause
        if len(chunk) > self.FILE_CHUNK_BYTES or incoming.received + len(chunk) > incoming.size:
            raise ValueError("file chunk exceeds the declared size")
        if not chunk and incoming.received < incoming.size:
            raise ValueError("empty file chunk cannot advance the transfer")
        with incoming.path.open("ab") as target:
            target.write(chunk)
        incoming.received += len(chunk)
        return self._transfer_response(wisp, {
            "type": "chunk_accepted",
            "transfer_id": transfer_id,
            "file_id": file_id,
            "next_offset": incoming.received,
        })

    async def _commit_file_action(self, sender: str, wisp: Wisp, body: dict[str, Any]) -> dict[str, Any]:
        transfer_id = str(body.get("transfer_id", ""))
        key = (sender, transfer_id)
        transfer = self._transfers.get(key)
        if transfer is None or transfer.wisp.id != wisp.id:
            raise ValueError("unknown file transfer")
        self._transfers.pop(key)
        try:
            incomplete = [file.name for file in transfer.files.values() if file.received != file.size]
            if incomplete:
                return self._transfer_response(wisp, {
                    "type": "error",
                    "transfer_id": transfer_id,
                    "error": "incomplete file transfer",
                })
            grouped: dict[str, list[UploadedFile]] = {}
            for file in transfer.files.values():
                grouped.setdefault(file.field, []).append(
                    UploadedFile(file.field, file.name, file.content_type, file.size, file.path)
                )
            exposed: dict[str, UploadedFile | tuple[UploadedFile, ...]] = {
                field: items[0] if len(items) == 1 else tuple(items)
                for field, items in grouped.items()
            }
            result = wisp.action(WispAction(transfer.action_data, exposed))
            state = await result if asyncio.iscoroutine(result) else result
            return {"wisp_id": wisp.id, "response": state}
        finally:
            self._cleanup_transfer(transfer)

    @staticmethod
    def _cleanup_transfer(transfer: _IncomingTransfer) -> None:
        shutil.rmtree(transfer.directory, ignore_errors=True)

    def _expire_file_transfers(self) -> None:
        cutoff = time.monotonic() - self.FILE_TRANSFER_TIMEOUT_SECONDS
        expired = [key for key, transfer in self._transfers.items() if transfer.created_at < cutoff]
        for key in expired:
            self._cleanup_transfer(self._transfers.pop(key))

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
