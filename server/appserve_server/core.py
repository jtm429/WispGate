from __future__ import annotations

import base64
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value.encode("ascii") + b"=" * (-len(value) % 4))


def _oaep_encrypt(key, value: bytes) -> bytes:
    return key.encrypt(value, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None,
    ))


def _oaep_decrypt(key, value: bytes) -> bytes:
    return key.decrypt(value, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None,
    ))


def _seal(public_key, payload: bytes) -> bytes:
    content_key = os.urandom(32)
    nonce = os.urandom(12)
    envelope = {
        "key": _b64(_oaep_encrypt(public_key, content_key)),
        "nonce": _b64(nonce),
        "ciphertext": _b64(AESGCM(content_key).encrypt(nonce, payload, None)),
    }
    return json.dumps(envelope, separators=(",", ":")).encode("ascii")


def _open(private_key, message: bytes) -> bytes:
    envelope = json.loads(message)
    return AESGCM(_oaep_decrypt(private_key, _unb64(envelope["key"]))).decrypt(
        _unb64(envelope["nonce"]), _unb64(envelope["ciphertext"]), None
    )


def build_bootstrap_request(relay_public_key, client_id: str, client_public_key, nonce: bytes, client_kind: str = "unknown") -> bytes:
    payload = json.dumps({
        "version": 1,
        "client_id": client_id,
        "client_kind": client_kind,
        "client_public_key": _b64u(client_public_key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
        )),
        "nonce": _b64(nonce),
    }, separators=(",", ":")).encode("utf-8")
    return _b64u(_seal(relay_public_key, payload)).encode("ascii")


def decrypt_bootstrap_request(relay_private_key, message: bytes) -> dict[str, Any]:
    payload = json.loads(_open(relay_private_key, _unb64(message.decode("ascii"))))
    if payload.get("version") != 1 or not isinstance(payload.get("client_id"), str) or not isinstance(payload.get("client_kind", "unknown"), str):
        raise ValueError("invalid bootstrap request")
    client_key = serialization.load_der_public_key(_unb64(payload["client_public_key"]))
    nonce = _unb64(payload["nonce"])
    if not isinstance(client_key, rsa.RSAPublicKey) or len(nonce) < 16:
        raise ValueError("invalid bootstrap request")
    return {"client_id": payload["client_id"], "client_kind": payload.get("client_kind", "unknown"), "client_public_key": client_key, "nonce": nonce}


def build_bootstrap_response(client_public_key, nonce: bytes, certificate_der: bytes) -> bytes:
    payload = json.dumps({
        "version": 1,
        "nonce": _b64u(nonce),

        "certificate_der": _b64u(certificate_der),
        "certificate_sha256": _b64u(__import__("hashlib").sha256(certificate_der).digest()),
    }, separators=(",", ":")).encode("utf-8")
    return _b64u(_seal(client_public_key, payload)).encode("ascii")


def decrypt_bootstrap_response(client_private_key, message: bytes, expected_nonce: bytes) -> dict[str, bytes]:
    payload = json.loads(_open(client_private_key, _unb64(message.decode("ascii"))))
    nonce = _unb64(payload["nonce"])
    if nonce != expected_nonce:
        raise ValueError("bootstrap nonce mismatch")
    certificate_der = _unb64(payload["certificate_der"])
    certificate_sha256 = _unb64(payload["certificate_sha256"])
    if certificate_sha256 != __import__("hashlib").sha256(certificate_der).digest():
        raise ValueError("bootstrap certificate hash mismatch")
    return {
        "nonce": nonce,

        "certificate_der": certificate_der,
        "certificate_sha256": certificate_sha256,
    }


@dataclass
class RelayConfig:
    server_private_key: bytes
    deployment_id: str = "private"
    max_bootstrap_age: int = 300
    enrollment_enabled: bool = False

    def private_key(self):
        return serialization.load_pem_private_key(self.server_private_key, password=None)

    def public_key_text(self) -> str:
        key = self.private_key().public_key()
        return _b64(
            key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )


def generate_server_keypair(path: Path) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    os.chmod(path, 0o600)
    return _b64(
        key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def build_bootstrap(config: RelayConfig, payload: dict[str, Any]) -> bytes:
    body = dict(payload)
    body.setdefault("deployment_id", config.deployment_id)
    body.setdefault("nonce", secrets.token_urlsafe(24))
    body.setdefault("timestamp", int(time.time()))
    encoded = json.dumps(body, separators=(",", ":")).encode("utf-8")
    key = config.private_key().public_key()
    encrypted = key.encrypt(
        encoded,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return _b64(encrypted).encode("ascii")


def parse_bootstrap(config: RelayConfig, message: bytes) -> dict[str, Any]:
    key = config.private_key()
    encoded = key.decrypt(
        _unb64(message.decode("ascii")),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    payload = json.loads(encoded)
    if payload.get("deployment_id") != config.deployment_id:
        raise ValueError("wrong deployment")
    if abs(int(time.time()) - int(payload["timestamp"])) > config.max_bootstrap_age:
        raise ValueError("stale bootstrap")
    return payload


class RelayState:
    def __init__(self, path: Path, max_queue_per_client: int = 100):
        self.path = Path(path)
        self.max_queue_per_client = max_queue_per_client
        self.clients: dict[str, dict[str, Any]] = {}
        self.queues: dict[str, list[dict[str, Any]]] = {}
        self.wisps: dict[str, dict[str, Any]] = {}
        self._enrollment_lock = threading.RLock()

    def load(self) -> None:
        if not self.path.exists():
            return
        data = json.loads(self.path.read_text(encoding="utf-8"))
        self.clients = data.get("clients", {})
        self.queues = data.get("queues", {})
        self.wisps = data.get("wisps", {})
        for record in self.clients.values():
            record.setdefault("status", "approved")
            record.setdefault("admin", False)

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps({"clients": self.clients, "queues": self.queues, "wisps": self.wisps}), encoding="utf-8")
        temporary.replace(self.path)

    def register_client(self, client_id: str, public_key: str, *, replace: bool = True) -> None:
        record = self.clients.setdefault(client_id, {})
        known = record.get("public_key")
        if known is not None and known != public_key:
            raise ValueError(f"client public key changed for {client_id}")
        if replace or known is None:
            record["public_key"] = public_key
        record["last_seen"] = int(time.time())

    def enroll_client(self, client_id: str, public_key: str, *, client_kind: str = "unknown") -> str:
        """Atomically admit a key; only an explicitly identified Android endpoint may become first admin."""
        with self._enrollment_lock:
            record = self.clients.get(client_id)
            if record is not None:
                if record.get("public_key") != public_key:
                    raise ValueError(f"client public key changed for {client_id}")
                return "admin" if record.get("admin") else str(record.get("status", "pending"))
            has_admin = any(item.get("admin") and item.get("status") == "approved" for item in self.clients.values())
            eligible = client_kind == "android"
            self.clients[client_id] = {
                "public_key": public_key,
                "client_kind": client_kind,
                "status": "approved" if eligible and not has_admin else "pending",
                "admin": eligible and not has_admin,
                "last_seen": int(time.time()),
            }
            self.save()
            return "admin" if eligible and not has_admin else "pending"

    def client_access(self, client_id: str, public_key: str) -> str:
        record = self.clients.get(client_id)
        if record is None:
            return "unknown_endpoint"
        if record.get("public_key") != public_key:
            return "endpoint_key_changed"
        return str(record.get("status", "approved"))

    def set_client_status(self, client_id: str, status: str) -> None:
        if status not in {"approved", "rejected", "revoked", "pending"}:
            raise ValueError("invalid endpoint status")
        if client_id not in self.clients:
            raise KeyError(client_id)
        self.clients[client_id]["status"] = status
        if status != "approved":
            self.clients[client_id]["admin"] = False
        self.save()

    def queue(self, client_id: str, envelope: dict[str, Any]) -> None:
        queue = self.queues.setdefault(client_id, [])
        queue.append(envelope)
        del queue[:-self.max_queue_per_client]

    def drain(self, client_id: str) -> list[dict[str, Any]]:
        result = self.queues.pop(client_id, [])
        return result

    def remove_wisps_for_owner(self, owner: str) -> None:
        self.wisps = {
            wisp_id: manifest
            for wisp_id, manifest in self.wisps.items()
            if manifest.get("owner") != owner
        }
