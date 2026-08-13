from __future__ import annotations

import base64
import json
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value.encode("ascii"))


@dataclass
class RelayConfig:
    server_private_key: bytes
    deployment_id: str = "private"
    max_bootstrap_age: int = 300

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

    def load(self) -> None:
        if not self.path.exists():
            return
        data = json.loads(self.path.read_text(encoding="utf-8"))
        self.clients = data.get("clients", {})
        self.queues = data.get("queues", {})
        self.wisps = data.get("wisps", {})

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps({"clients": self.clients, "queues": self.queues, "wisps": self.wisps}), encoding="utf-8")
        temporary.replace(self.path)

    def register_client(self, client_id: str, public_key: str) -> None:
        record = self.clients.setdefault(client_id, {})
        record["public_key"] = public_key
        record["last_seen"] = int(time.time())

    def queue(self, client_id: str, envelope: dict[str, Any]) -> None:
        queue = self.queues.setdefault(client_id, [])
        queue.append(envelope)
        del queue[:-self.max_queue_per_client]

    def drain(self, client_id: str) -> list[dict[str, Any]]:
        result = self.queues.pop(client_id, [])
        return result
