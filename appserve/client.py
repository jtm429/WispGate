from __future__ import annotations

import asyncio
import base64
import io
import inspect
import json
import logging
import re
import secrets
import shutil
import ssl
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, BinaryIO, Callable

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from server.appserve_server.core import build_bootstrap_request, decrypt_bootstrap_response

from .e2e import (
    PeerSession,
    decrypt_envelope,
    derive_session_keys,
    encrypt_envelope,
    generate_identity,
    load_or_create_identity,
    public_key_text,
    session_accept_proof,
)


LOG = logging.getLogger(__name__)
_ASSET_ID_PATTERN = re.compile(r"[A-Za-z0-9._~-]+")


async def _invoke_wisp_callback(callback: Callable[..., Any], *args: Any) -> Any:
    """Keep synchronous Wisp code from blocking relay and control I/O."""
    result = await asyncio.to_thread(callback, *args)
    return await result if inspect.isawaitable(result) else result


@dataclass(frozen=True)
class ServerInfo:
    host: str
    control_port: int
    relay_port: int
    server_public_key: bytes
    deployment_id: str = "private"
    bulk_port: int = 4444

@dataclass
class Wisp:
    id: str
    name: str
    description: str
    state: Callable[[], "WispResponse | dict[str, Any]"]
    action: Callable[[dict[str, Any]], Awaitable["WispResponse | dict[str, Any]"] | "WispResponse | dict[str, Any]"]

    def manifest(self) -> dict[str, str]:
        return {"id": self.id, "name": self.name, "description": self.description}


@dataclass(frozen=True)
class WispAsset:
    """A response asset streamed through WispGate's encrypted bulk lane."""

    id: str
    name: str
    content_type: str
    size: int
    _open: Callable[[], BinaryIO]

    @classmethod
    def from_bytes(cls, id: str, name: str, content_type: str, data: bytes) -> "WispAsset":
        value = bytes(data)
        return cls(id, name, content_type, len(value), lambda: io.BytesIO(value))

    @classmethod
    def from_path(cls, id: str, path: str | Path, content_type: str) -> "WispAsset":
        source = Path(path)
        return cls(id, source.name, content_type, source.stat().st_size, lambda: source.open("rb"))

    def open(self) -> BinaryIO:
        return self._open()


@dataclass(frozen=True)
class WispResponse:
    html: str
    assets: tuple[WispAsset, ...] = ()
    content_type: str = "text/html"

    def payload(self) -> dict[str, str]:
        return {"content_type": self.content_type, "html": self.html}


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
    bulk: dict[str, Any] | None = None


@dataclass
class _IncomingTransfer:
    sender: str
    wisp: Wisp
    action_data: dict[str, Any]
    directory: Path
    files: dict[str, _IncomingFile]
    created_at: float
    task: asyncio.Task[None] | None = None


@dataclass(frozen=True)
class _PreparedOutboundAsset:
    asset: WispAsset
    transfer_id: str
    sender: str
    recipient: str
    ticket: str
    encrypted_key: str
    nonce: str
    content_key: bytes

    @property
    def ciphertext_size(self) -> int:
        return self.asset.size + 16

    def aad(self) -> bytes:
        return b"\0".join([
            b"wispgate-bulk-v1",
            self.sender.encode(),
            self.recipient.encode(),
            self.transfer_id.encode(),
            self.asset.id.encode(),
            self.ticket.encode(),
            str(self.asset.size).encode(),
        ])


class AppserveClient:
    MAX_FILES_PER_ACTION = 32
    MAX_FILE_ACTION_BYTES = 256 * 1024 * 1024
    MAX_ACTIVE_TRANSFERS_PER_SENDER = 4
    FILE_TRANSFER_TIMEOUT_SECONDS = 10 * 60
    HEARTBEAT_INTERVAL_SECONDS = 25.0
    COMPLETED_OPERATION_TTL_SECONDS = 15 * 60

    def __init__(
        self,
        info: ServerInfo,
        client_id: str,
        *,
        identity_key=None,
        peer_store_path: str | Path | None = None,
        transfer_directory: str | Path | None = None,
        trust_anchor_path: str | Path | None = None,
        client_kind: str = "python-wisp",
    ):
        self.info = info
        self.client_id = client_id
        self.client_kind = client_kind

        self._writer: asyncio.StreamWriter | None = None
        self._wisps: dict[str, Wisp] = {}
        self._identity_key = identity_key or generate_identity()
        self._trust_anchor_path = Path(trust_anchor_path) if trust_anchor_path else None
        self._tls_anchor_sha256 = None
        if self._trust_anchor_path and self._trust_anchor_path.exists():
            cached = json.loads(self._trust_anchor_path.read_text(encoding="utf-8"))
            if isinstance(cached, dict) and re.fullmatch(r"[0-9a-f]{64}", str(cached.get("sha256", ""))):
                self._tls_anchor_sha256 = str(cached["sha256"])
        self._peer_store_path = Path(peer_store_path) if peer_store_path else None
        self._transfer_directory = Path(transfer_directory) if transfer_directory else Path(tempfile.gettempdir()) / "wispgate-transfers"
        self._transfers: dict[tuple[str, str], _IncomingTransfer] = {}
        self._peer_keys: dict[str, str] = {}
        self._peer_sessions: dict[str, PeerSession] = {}
        self._completed_operations: dict[tuple[str, str], tuple[float, dict[str, Any]]] = {}
        self._active_operations: set[tuple[str, str]] = set()
        self._operation_tasks: set[asyncio.Task[None]] = set()
        self._send_lock = asyncio.Lock()
        self._relay_ready = asyncio.Event()
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
                except Exception as cause:
                    self._close_connection()
                    LOG.exception("Wisp runtime attempt failed; restarting from bootstrap in %.1fs: %s", delay, cause)
                    await asyncio.sleep(delay)
                    delay = min(delay * 2, 30.0)
        finally:
            await self.close()

    async def _serve_once(self) -> None:
        reader, writer = await self._open_tls(self.info.control_port)
        self._enable_tcp_keepalive(writer)
        self._reader, self._writer = reader, writer
        try:
            await self._authenticate_endpoint(writer, reader, "control")
            bootstrap = self._bootstrap_payload()
            await self._send(writer, {"type": "join", "payload": bootstrap})
            joined = await self._read(reader)
            if not joined.get("ok"):
                raise ConnectionError(joined.get("error", "join failed"))
            await self._send(writer, self._registration_message())
            registration = await asyncio.wait_for(self._read(reader), timeout=10)
            if not registration.get("ok") or registration.get("type") != "wisps_registered":
                raise ConnectionError(registration.get("error", "Wisp registration rejected"))
            registered_ids = [item.get("id") for item in registration.get("items", []) if isinstance(item, dict)]
            LOG.info("Wisp registration accepted client=%s ids=%s", self.client_id, registered_ids)
        finally:
            writer.close()
            await writer.wait_closed()
            self._reader = self._writer = None

        reader, writer = await self._open_tls(self.info.relay_port)
        self._enable_tcp_keepalive(writer)
        self._reader, self._writer = reader, writer
        await self._authenticate_endpoint(writer, reader, "relay")
        ready = await self._read(reader)
        if not ready.get("ok"):
            raise ConnectionError(ready.get("error", "session failed"))
        self._relay_ready.set()
        heartbeat = asyncio.create_task(self._heartbeat_loop())
        try:
            await self._event_loop()
        finally:
            heartbeat.cancel()
            await asyncio.gather(heartbeat, return_exceptions=True)

    async def close(self) -> None:
        self._relay_ready.clear()
        writer = self._writer
        self._reader = self._writer = None
        self._peer_sessions.clear()
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass
        tasks = [transfer.task for transfer in self._transfers.values() if transfer.task is not None]
        tasks.extend(self._operation_tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._operation_tasks.clear()
        self._active_operations.clear()
        for transfer in list(self._transfers.values()):
            self._cleanup_transfer(transfer)
        self._transfers.clear()

    def _close_connection(self) -> None:
        self._relay_ready.clear()
        if self._writer is not None:
            self._writer.close()
        self._reader = self._writer = None

    async def _event_loop(self) -> None:
        assert self._reader is not None
        while line := await self._reader.readline():
            message = json.loads(line)
            if message.get("type") == "ping":
                nonce = message.get("nonce")
                if isinstance(nonce, str) and nonce:
                    async with self._send_lock:
                        if self._writer is not None:
                            await self._send(self._writer, {"type": "pong", "nonce": nonce})
            elif message.get("type") == "pong":
                LOG.debug("relay heartbeat acknowledged")
            elif message.get("type") == "envelope":
                await self._handle_envelope(message)
            elif message.get("type") == "session_envelope":
                try:
                    await self._handle_session_envelope(message, background_mutations=True)
                except ValueError as cause:
                    if str(cause) == "unknown session":
                        LOG.warning("rejected unknown peer session; requested a fresh session from sender")
                    else:
                        LOG.warning("discarding invalid peer-session frame: %s", cause)
            elif message.get("type") == "session_reset":
                if message.get("recipient") != self.client_id:
                    LOG.warning("discarding invalid session-reset route")
                else:
                    self._peer_sessions.pop(message.get("sender"), None)
                    LOG.warning("peer %s requested a fresh session: %s", message.get("sender"), message.get("reason", "unknown"))
            elif message.get("type") == "accepted":
                # Relay transport acknowledgement. It is not Wisp application data.
                LOG.debug("relay accepted forwarded message type=%s", message.get("message_type", "session_envelope"))
            elif message.get("type") is None and message.get("ok") is True:
                # Compatibility with relays that acknowledge a forwarded control packet
                # using the original success-only response shape.
                LOG.debug("relay accepted forwarded message (legacy acknowledgement)")
            elif message.get("type") is None and message.get("ok") is False:
                LOG.warning("relay rejected forwarded message: %s", message.get("error", "unknown error"))
            else:
                LOG.warning("discarding unknown relay message type: %s", message.get("type"))

    async def _heartbeat_loop(self) -> None:
        while True:
            await asyncio.sleep(self.HEARTBEAT_INTERVAL_SECONDS)
            await self._relay_ready.wait()
            async with self._send_lock:
                writer = self._writer
                if writer is not None:
                    await self._send(writer, {"type": "ping", "nonce": secrets.token_urlsafe(12)})

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
        if message.get("recipient") != self.client_id:
            raise ValueError("invalid handshake route")
        body, sender_key = decrypt_envelope(message, self._identity_key, self._peer_keys.get(sender))
        self._remember_peer(sender, sender_key)
        if body.get("type") != "session_init":
            raise ValueError("RSA envelope must contain session_init")
        session_id = body.get("session_id")
        challenge = body.get("challenge")
        encoded_master = body.get("master_secret")
        if not all(isinstance(value, str) and value for value in (session_id, challenge, encoded_master)):
            raise ValueError("invalid session_init")
        master = base64.urlsafe_b64decode(encoded_master + "=" * (-len(encoded_master) % 4))
        if len(master) != 32:
            raise ValueError("invalid session master secret")
        android_to_wisp, wisp_to_android = derive_session_keys(master, session_id)
        self._peer_sessions[sender] = PeerSession(
            session_id, self.client_id, sender, android_to_wisp, wisp_to_android, created_at=time.monotonic()
        )
        await self._send_envelope(sender, {
            "type": "session_accept", "session_id": session_id, "challenge": challenge,
            "proof": session_accept_proof(master, session_id, challenge, sender, self.client_id),
        })

    async def _handle_session_envelope(
        self,
        message: dict[str, Any],
        *,
        background_mutations: bool = False,
    ) -> None:
        sender = message.get("sender")
        session = self._peer_sessions.get(sender)
        if session is None:
            await self._send_session_reset(sender, "unknown_session")
            raise ValueError("unknown session")
        try:
            body = session.decrypt(message, now=time.monotonic())
        except Exception as cause:
            self._peer_sessions.pop(sender, None)
            raise ValueError(str(cause)) from cause
        await self._dispatch_session_body(
            sender, body, background_mutations=background_mutations
        )

    async def _send_session_reset(self, recipient: str, reason: str) -> None:
        if not self._writer:
            return
        await self._send(self._writer, {
            "type": "session_reset",
            "sender": self.client_id,
            "recipient": recipient,
            "reason": reason,
        })

    async def _dispatch_session_body(
        self,
        sender: str,
        body: dict[str, Any],
        *,
        background_mutations: bool = False,
    ) -> None:
        await self._expire_file_transfers()
        self._expire_completed_operations()
        wisp = self._wisps.get(body.get("wisp_id"))
        if not wisp:
            return
        action_kind = body.get("action")
        if action_kind == "operation_resume":
            operation_id = str(body.get("operation_id", ""))
            key = (sender, operation_id)
            completed = self._completed_operations.get(key)
            if completed is not None:
                response = dict(completed[1])
                response.setdefault(
                    "operation", {"type": "completed", "operation_id": operation_id}
                )
                await self._send_session(sender, response)
            elif key in self._transfers or key in self._active_operations:
                await self._send_session(sender, {
                    "wisp_id": wisp.id,
                    "operation": {"type": "running", "operation_id": operation_id},
                })
            else:
                await self._send_session(sender, {
                    "wisp_id": wisp.id,
                    "operation": {"type": "expired", "operation_id": operation_id},
                })
            return
        if action_kind == "state_request":
            state = await _invoke_wisp_callback(wisp.state)
        elif action_kind == "file_begin":
            transfer_id = str(body.get("transfer_id", ""))
            completed = self._completed_operations.get((sender, transfer_id))
            if completed is not None:
                await self._send_session(sender, completed[1])
                return
            if (sender, transfer_id) in self._transfers:
                await self._send_session(
                    sender, self._operation_status_body(wisp, "running", transfer_id)
                )
                return
            try:
                response = self._begin_file_action(sender, wisp, body)
            except (KeyError, TypeError, ValueError) as cause:
                transfer = self._transfers.pop((sender, transfer_id), None)
                if transfer is not None:
                    self._cleanup_transfer(transfer)
                response = self._transfer_response(wisp, {
                    "type": "error",
                    "transfer_id": transfer_id,
                    "error": str(cause),
                })
            await self._send_session(sender, response)
            transfer = self._transfers.get((sender, transfer_id))
            if transfer is not None:
                transfer.task = asyncio.create_task(self._receive_bulk_transfer(transfer_id, transfer))
            return
        else:
            operation_id = body.get("operation_id")
            if not isinstance(operation_id, str) or not operation_id or len(operation_id) > 128:
                await self._send_session(sender, self._operation_status_body(
                    wisp, "invalid", "", "mutating action requires a stable operation_id"
                ))
                return
            key = (sender, operation_id)
            completed = self._completed_operations.get(key)
            if completed is not None:
                await self._send_session(sender, completed[1])
                return
            if key in self._active_operations:
                await self._send_session(sender, self._operation_status_body(wisp, "running", operation_id))
                return
            self._active_operations.add(key)
            try:
                state = await _invoke_wisp_callback(wisp.action, WispAction(body.get("action_data", {})))
            except Exception:
                retained = self._operation_status_body(wisp, "indeterminate", operation_id)
                self._remember_completed_operation(sender, operation_id, retained)
                raise
            finally:
                self._active_operations.discard(key)
            retained = self._retained_response_body(wisp, state)
            if retained is not None:
                self._remember_completed_operation(sender, operation_id, retained)
        await self._send_wisp_response(sender, wisp, state)

    def _transfer_response(self, wisp: Wisp, transfer: dict[str, Any]) -> dict[str, Any]:
        return {"wisp_id": wisp.id, "transfer": transfer}

    @staticmethod
    def _operation_status_body(
        wisp: Wisp, status: str, operation_id: str, error: str | None = None
    ) -> dict[str, Any]:
        operation: dict[str, Any] = {"type": status, "operation_id": operation_id}
        if error is not None:
            operation["error"] = error
        return {"wisp_id": wisp.id, "operation": operation}

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
                bulk = manifest.get("bulk")
                if not isinstance(bulk, dict):
                    raise ValueError("file manifest requires bulk transport metadata")
                ticket = bulk.get("ticket")
                encrypted_key = bulk.get("encrypted_key")
                nonce = bulk.get("nonce")
                ciphertext_size = bulk.get("ciphertext_size")
                if (
                    bulk.get("algorithm") != "RSA-OAEP-256+A256GCM"
                    or not isinstance(ticket, str) or not 16 <= len(ticket) <= 256
                    or not isinstance(encrypted_key, str) or not encrypted_key
                    or not isinstance(nonce, str) or not nonce
                    or ciphertext_size != size + 16
                ):
                    raise ValueError("invalid bulk transport metadata")
                files[file_id] = _IncomingFile(
                    file_id, field, name, content_type, size, path, bulk=dict(bulk)
                )
        except Exception:
            shutil.rmtree(directory, ignore_errors=True)
            raise

        self._transfers[key] = _IncomingTransfer(sender, wisp, dict(action_data), directory, files, time.monotonic())
        return self._transfer_response(wisp, {
            "type": "ready",
            "transfer_id": transfer_id,
        })

    async def _receive_bulk_transfer(self, transfer_id: str, transfer: _IncomingTransfer) -> None:
        key = (transfer.sender, transfer_id)
        try:
            try:
                for incoming in transfer.files.values():
                    await self._receive_bulk_file(transfer.sender, transfer_id, incoming)
                grouped: dict[str, list[UploadedFile]] = {}
                for file in transfer.files.values():
                    grouped.setdefault(file.field, []).append(
                        UploadedFile(file.field, file.name, file.content_type, file.size, file.path)
                    )
                exposed: dict[str, UploadedFile | tuple[UploadedFile, ...]] = {
                    field: items[0] if len(items) == 1 else tuple(items)
                    for field, items in grouped.items()
                }
                state = await _invoke_wisp_callback(
                    transfer.wisp.action,
                    WispAction(transfer.action_data, exposed),
                )
            except asyncio.CancelledError:
                raise
            except Exception as cause:
                LOG.exception(
                    "bulk transfer failed sender=%s transfer=%s",
                    transfer.sender,
                    transfer_id,
                )
                response = self._transfer_response(transfer.wisp, {
                    "type": "error",
                    "transfer_id": transfer_id,
                    "error": str(cause),
                })
                self._remember_completed_operation(transfer.sender, transfer_id, response)
                try:
                    await self._send_session(transfer.sender, response)
                except (ConnectionError, OSError, ValueError):
                    LOG.warning(
                        "retained failed bulk operation after delivery failure sender=%s transfer=%s",
                        transfer.sender,
                        transfer_id,
                    )
                return

            retained = self._retained_response_body(transfer.wisp, state)
            if retained is None:
                retained = self._operation_status_body(
                    transfer.wisp, "indeterminate", transfer_id
                )
            self._remember_completed_operation(transfer.sender, transfer_id, retained)
            try:
                await self._send_wisp_response(transfer.sender, transfer.wisp, state)
            except (ConnectionError, OSError, ValueError):
                LOG.warning(
                    "retained successful bulk operation after delivery failure sender=%s transfer=%s",
                    transfer.sender,
                    transfer_id,
                )
        finally:
            self._transfers.pop(key, None)
            self._cleanup_transfer(transfer)

    async def _receive_bulk_file(self, sender: str, transfer_id: str, incoming: _IncomingFile) -> None:
        assert incoming.bulk is not None
        bulk = incoming.bulk
        encrypted_key = base64.urlsafe_b64decode(bulk["encrypted_key"] + "=" * (-len(bulk["encrypted_key"]) % 4))
        nonce = base64.urlsafe_b64decode(bulk["nonce"] + "=" * (-len(bulk["nonce"]) % 4))
        if len(nonce) != 12:
            raise ValueError("invalid bulk nonce")
        file_key = self._identity_key.decrypt(
            encrypted_key,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA256(), label=None),
        )
        if len(file_key) != 32:
            raise ValueError("invalid bulk content key")
        reader, writer = await self._open_tls(self.info.bulk_port)
        try:
            await self._send(writer, {
                "type": "auth_hello",
                "role": "bulk_receiver",
                "client_id": self.client_id,
                "public_key": public_key_text(self._identity_key),
                "ticket": bulk["ticket"],
                "peer": sender,
                "length": bulk["ciphertext_size"],
            })
            await self._complete_auth(reader, writer, "bulk_receiver", bulk["ticket"], sender, bulk["ciphertext_size"])
            ready = await self._read(reader)
            if not ready.get("ok") or ready.get("type") != "bulk_ready":
                raise ConnectionError(ready.get("error", "bulk relay rejected transfer"))
            aad = b"\0".join([
                b"wispgate-bulk-v1",
                sender.encode(),
                self.client_id.encode(),
                transfer_id.encode(),
                incoming.id.encode(),
                bulk["ticket"].encode(),
                str(incoming.size).encode(),
            ])
            decryptor = Cipher(algorithms.AES(file_key), modes.GCM(nonce)).decryptor()
            decryptor.authenticate_additional_data(aad)
            remaining = bulk["ciphertext_size"] - 16
            written = 0
            with incoming.path.open("wb") as target:
                while remaining:
                    chunk = await reader.readexactly(min(256 * 1024, remaining))
                    plaintext = decryptor.update(chunk)
                    target.write(plaintext)
                    written += len(plaintext)
                    remaining -= len(chunk)
                tag = await reader.readexactly(16)
                final = decryptor.finalize_with_tag(tag)
                target.write(final)
                written += len(final)
            if written != incoming.size:
                raise ValueError("bulk file length did not match its manifest")
            incoming.received = written
        finally:
            writer.close()
            await writer.wait_closed()


    @staticmethod
    def _cleanup_transfer(transfer: _IncomingTransfer) -> None:
        shutil.rmtree(transfer.directory, ignore_errors=True)

    async def _expire_file_transfers(self) -> None:
        cutoff = time.monotonic() - self.FILE_TRANSFER_TIMEOUT_SECONDS
        expired = [(key, transfer) for key, transfer in self._transfers.items() if transfer.created_at < cutoff]
        tasks: list[asyncio.Task[None]] = []
        for (sender, operation_id), transfer in expired:
            self._remember_completed_operation(
                sender,
                operation_id,
                self._operation_status_body(transfer.wisp, "indeterminate", operation_id),
            )
            if transfer.task is not None and not transfer.task.done():
                transfer.task.cancel()
                tasks.append(transfer.task)
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        for key, transfer in expired:
            self._transfers.pop(key, None)
            self._cleanup_transfer(transfer)

    def _remember_completed_operation(self, sender: str, operation_id: str, body: dict[str, Any]) -> None:
        if operation_id:
            self._completed_operations[(sender, operation_id)] = (time.monotonic(), body)

    def _expire_completed_operations(self) -> None:
        cutoff = time.monotonic() - self.COMPLETED_OPERATION_TTL_SECONDS
        self._completed_operations = {
            key: value for key, value in self._completed_operations.items() if value[0] >= cutoff
        }

    @staticmethod
    def _retained_response_body(wisp: Wisp, state: WispResponse | dict[str, Any]) -> dict[str, Any] | None:
        if isinstance(state, WispResponse):
            if state.assets:
                return None
            payload = state.payload()
        else:
            payload = state
        return {"wisp_id": wisp.id, "response": payload}

    async def _send_wisp_response(
        self,
        recipient: str,
        wisp: Wisp,
        state: WispResponse | dict[str, Any],
    ) -> None:
        if not isinstance(state, WispResponse) or not state.assets:
            payload = state.payload() if isinstance(state, WispResponse) else state
            await self._send_session(recipient, {"wisp_id": wisp.id, "response": payload})
            return

        prepared = self._prepare_outbound_assets(recipient, state.assets)
        transfer_id = prepared[0].transfer_id
        files = [
            {
                "id": item.asset.id,
                "name": item.asset.name,
                "content_type": item.asset.content_type,
                "size": item.asset.size,
                "bulk": {
                    "algorithm": "RSA-OAEP-256+A256GCM",
                    "ticket": item.ticket,
                    "encrypted_key": item.encrypted_key,
                    "nonce": item.nonce,
                    "ciphertext_size": item.ciphertext_size,
                },
            }
            for item in prepared
        ]
        await self._send_session(
            recipient,
            {
                "wisp_id": wisp.id,
                "response": state.payload(),
                "assets": {"type": "begin", "transfer_id": transfer_id, "files": files},
            },
        )
        for item in prepared:
            await self._send_outbound_asset(item)
        await self._send_session(
            recipient,
            {"wisp_id": wisp.id, "assets": {"type": "complete", "transfer_id": transfer_id}},
        )

    def _prepare_outbound_assets(
        self,
        recipient: str,
        assets: tuple[WispAsset, ...],
    ) -> list[_PreparedOutboundAsset]:
        if not 1 <= len(assets) <= self.MAX_FILES_PER_ACTION:
            raise ValueError("a Wisp response must contain between 1 and 32 assets")
        if any(type(asset.size) is not int for asset in assets):
            raise ValueError("invalid Wisp response asset")
        if sum(asset.size for asset in assets) > self.MAX_FILE_ACTION_BYTES:
            raise ValueError("Wisp response assets exceed the configured size limit")
        ids: set[str] = set()
        for asset in assets:
            if (
                not _ASSET_ID_PATTERN.fullmatch(asset.id) or asset.id in {".", ".."}
                or len(asset.id) > 128 or asset.id in ids
                or not asset.name or len(asset.name) > 512
                or not asset.content_type or len(asset.content_type) > 128
                or asset.size < 0
            ):
                raise ValueError("invalid Wisp response asset")
            ids.add(asset.id)
        peer_text = self._peer_keys.get(recipient)
        if not peer_text:
            raise ValueError(f"no trusted public key for {recipient}")
        peer_key = serialization.load_der_public_key(
            base64.urlsafe_b64decode(peer_text + "=" * (-len(peer_text) % 4))
        )
        transfer_id = secrets.token_urlsafe(18)
        prepared: list[_PreparedOutboundAsset] = []
        for asset in assets:
            content_key = secrets.token_bytes(32)
            nonce = secrets.token_bytes(12)
            ticket = secrets.token_urlsafe(24)
            wrapped = peer_key.encrypt(
                content_key,
                padding.OAEP(mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA256(), label=None),
            )
            prepared.append(
                _PreparedOutboundAsset(
                    asset,
                    transfer_id,
                    self.client_id,
                    recipient,
                    ticket,
                    base64.urlsafe_b64encode(wrapped).decode().rstrip("="),
                    base64.urlsafe_b64encode(nonce).decode().rstrip("="),
                    content_key,
                )
            )
        return prepared

    async def _send_outbound_asset(self, item: _PreparedOutboundAsset) -> None:
        reader, writer = await self._open_tls(self.info.bulk_port)
        try:
            await self._send(
                writer,
                {
                    "type": "auth_hello",
                    "role": "bulk_sender",
                    "client_id": self.client_id,
                    "public_key": public_key_text(self._identity_key),
                    "ticket": item.ticket,
                    "peer": item.recipient,
                    "length": item.ciphertext_size,
                },
            )
            await self._complete_auth(reader, writer, "bulk_sender", item.ticket, item.recipient, item.ciphertext_size)
            ready = await self._read(reader)
            if not ready.get("ok") or ready.get("type") != "bulk_ready":
                raise ConnectionError(ready.get("error", "bulk relay rejected transfer"))
            nonce = base64.urlsafe_b64decode(item.nonce + "=" * (-len(item.nonce) % 4))
            encryptor = Cipher(algorithms.AES(item.content_key), modes.GCM(nonce)).encryptor()
            encryptor.authenticate_additional_data(item.aad())
            plaintext_size = 0
            with item.asset.open() as source:
                while chunk := source.read(256 * 1024):
                    plaintext_size += len(chunk)
                    writer.write(encryptor.update(chunk))
                    await writer.drain()
            if plaintext_size != item.asset.size:
                raise ValueError("asset length changed during transfer")
            writer.write(encryptor.finalize() + encryptor.tag)
            await writer.drain()
            complete = await self._read(reader)
            if not complete.get("ok") or complete.get("type") != "bulk_complete":
                raise ConnectionError(complete.get("error", "bulk relay did not complete transfer"))
        finally:
            writer.close()
            await writer.wait_closed()

    async def _send_envelope(self, recipient: str, body: dict[str, Any]) -> None:
        assert self._writer is not None
        recipient_key = self._peer_keys.get(recipient)
        if not recipient_key:
            raise ValueError(f"no trusted public key for {recipient}")
        async with self._send_lock:
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

    async def _send_session(self, recipient: str, body: dict[str, Any]) -> None:
        while True:
            await self._relay_ready.wait()
            async with self._send_lock:
                writer = self._writer
                if writer is None:
                    continue
                session = self._peer_sessions.get(recipient)
                if session is None:
                    raise ValueError(f"no active session for {recipient}")
                await self._send(writer, session.encrypt(body, now=time.monotonic()))
                return

    def _bootstrap_payload(self) -> str:
        key = serialization.load_der_public_key(self.info.server_public_key)
        payload = json.dumps({
            "deployment_id": self.info.deployment_id,
            "client_id": self.client_id,
            "client_kind": self.client_kind,
            "client_public_key": public_key_text(self._identity_key),
            "nonce": secrets.token_urlsafe(20),
            "timestamp": int(time.time()),
        }, separators=(",", ":")).encode()
        encrypted = key.encrypt(
            payload,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA256(), label=None),
        )
        return base64.urlsafe_b64encode(encrypted).decode()

    async def _authenticate_endpoint(
        self, writer: asyncio.StreamWriter, reader: asyncio.StreamReader, role: str,
    ) -> None:
        await self._send(writer, {
            "type": "auth_hello", "role": role, "client_id": self.client_id,
            "client_kind": self.client_kind,
            "public_key": public_key_text(self._identity_key),
        })
        await self._complete_auth(reader, writer, role)

    async def _complete_auth(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, role: str = "",
        ticket: str = "", peer: str = "", length: int | str = "",
    ) -> None:
        challenge = await self._read(reader)
        if challenge.get("type") != "auth_challenge":
            raise ConnectionError(challenge.get("error", "relay did not issue an endpoint challenge"))
        transcript = f"wisp-relay-auth-v1\n{role}\n{self.client_id}\n{challenge['challenge']}\n{ticket}\n{peer}\n{length}".encode("ascii")
        signature = self._identity_key.sign(
            transcript,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
        await self._send(writer, {
            "type": "auth_proof",
            "signature": base64.urlsafe_b64encode(signature).decode().rstrip("="),
        })
        result = await self._read(reader)
        if not result.get("ok"):
            raise ConnectionError(result.get("error", "endpoint authentication rejected"))

    @staticmethod
    async def _send(writer: asyncio.StreamWriter, value: dict[str, Any]) -> None:
        writer.write(json.dumps(value, separators=(",", ":")).encode() + b"\n")
        await writer.drain()

    @staticmethod
    def _enable_tcp_keepalive(writer: asyncio.StreamWriter) -> None:
        sock = writer.get_extra_info("socket")
        if sock is not None:
            import socket
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

    async def _open_tls(self, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        if self._tls_anchor_sha256 is None:
            await self._bootstrap_tls()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        reader, writer = await asyncio.open_connection(
            self.info.host,
            port,
            ssl=context,
            server_hostname=None,
        )
        ssl_object = writer.get_extra_info("ssl_object")
        certificate = ssl_object.getpeercert(binary_form=True) if ssl_object else None
        if certificate is None:
            writer.close()
            await writer.wait_closed()
            raise ssl.SSLError("TLS peer did not present a certificate")
        import hashlib
        actual = hashlib.sha256(certificate).hexdigest()
        if not secrets.compare_digest(actual, self._tls_anchor_sha256 or ""):
            writer.close()
            await writer.wait_closed()
            raise ssl.SSLError("TLS leaf certificate fingerprint mismatch")
        return reader, writer

    async def _bootstrap_tls(self) -> None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        reader, writer = await asyncio.open_connection(self.info.host, self.info.control_port, ssl=context)
        nonce = secrets.token_bytes(24)
        payload = build_bootstrap_request(
            serialization.load_der_public_key(self.info.server_public_key),
            self.client_id,
            self._identity_key.public_key(),
            nonce,
            self.client_kind,
        )
        try:
            await self._send(writer, {"type": "bootstrap_request", "payload": payload.decode("ascii")})
            result = await self._read(reader)
            if not result.get("ok") or result.get("type") != "bootstrap_response":
                raise ssl.SSLError(result.get("error", "encrypted bootstrap rejected"))
            response = decrypt_bootstrap_response(
                self._identity_key, result["payload"].encode("ascii"), nonce
            )
            import hashlib
            actual = hashlib.sha256(response["certificate_der"]).hexdigest()
            if actual != response["certificate_sha256"].hex():
                raise ssl.SSLError("encrypted bootstrap certificate hash mismatch")
            self._tls_anchor_sha256 = actual
            if self._trust_anchor_path:
                self._trust_anchor_path.parent.mkdir(parents=True, exist_ok=True)
                self._trust_anchor_path.write_text(json.dumps({"sha256": actual}), encoding="utf-8")
        finally:
            writer.close()
            await writer.wait_closed()

    @staticmethod
    async def _read(reader: asyncio.StreamReader) -> dict[str, Any]:
        return json.loads(await reader.readline())


def load(path: str | Path, *, reset_peer_trust: bool = False) -> AppserveClient:
    config_path = Path(path)
    data = json.loads(config_path.read_text(encoding="utf-8"))
    key = data["server_public_key"]
    client_id = data.get("client_id", "python-wisp")
    identity_path = config_path.with_name(f".{config_path.stem}-{client_id}-identity.pem")
    peers_path = config_path.with_name(f".{config_path.stem}-{client_id}-peers.json")
    if reset_peer_trust:
        peers_path.unlink(missing_ok=True)
    return AppserveClient(
        ServerInfo(
            host=data["server"],
            control_port=int(data.get("control_port", data.get("port", 443))),
            relay_port=int(data.get("relay_port", 4443)),
            server_public_key=base64.urlsafe_b64decode(key),
            deployment_id=data.get("deployment_id", "private"),
            bulk_port=int(data.get("bulk_port", 4444)),
        ),
        client_id=client_id,
        identity_key=load_or_create_identity(identity_path),
        peer_store_path=peers_path,
        trust_anchor_path=config_path.with_name(f".{config_path.stem}-{client_id}-tls-anchor.json"),
    )
