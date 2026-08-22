"""Client-side relay bootstrap encryption/decryption.

This module intentionally contains no relay server state or listener code. It is
safe for Python Wisp runtimes and other clients to import without importing the
relay implementation.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
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


def _oaep_encrypt(key: rsa.RSAPublicKey, value: bytes) -> bytes:
    return key.encrypt(value, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA1()),
        algorithm=hashes.SHA256(),
        label=None,
    ))


def _oaep_decrypt(key: rsa.RSAPrivateKey, value: bytes) -> bytes:
    return key.decrypt(value, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA1()),
        algorithm=hashes.SHA256(),
        label=None,
    ))


def _seal(public_key: rsa.RSAPublicKey, payload: bytes) -> bytes:
    content_key = os.urandom(32)
    nonce = os.urandom(12)
    envelope = {
        "key": _b64(_oaep_encrypt(public_key, content_key)),
        "nonce": _b64(nonce),
        "ciphertext": _b64(AESGCM(content_key).encrypt(nonce, payload, None)),
    }
    return json.dumps(envelope, separators=(",", ":")).encode("ascii")


def _open(private_key: rsa.RSAPrivateKey, message: bytes) -> bytes:
    envelope = json.loads(message)
    content_key = _oaep_decrypt(private_key, _unb64(envelope["key"]))
    return AESGCM(content_key).decrypt(
        _unb64(envelope["nonce"]), _unb64(envelope["ciphertext"]), None
    )


def build_bootstrap_request(
    relay_public_key: rsa.RSAPublicKey,
    client_id: str,
    client_public_key: rsa.RSAPublicKey,
    nonce: bytes,
    client_kind: str = "unknown",
) -> bytes:
    payload = json.dumps({
        "version": 1,
        "client_id": client_id,
        "client_kind": client_kind,
        "client_public_key": _b64u(client_public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )),
        "nonce": _b64(nonce),
    }, separators=(",", ":")).encode("utf-8")
    return _b64u(_seal(relay_public_key, payload)).encode("ascii")


def decrypt_bootstrap_response(
    client_private_key: rsa.RSAPrivateKey,
    message: bytes,
    expected_nonce: bytes,
) -> dict[str, bytes]:
    payload = json.loads(_open(client_private_key, _unb64(message.decode("ascii"))))
    nonce = _unb64(payload["nonce"])
    if nonce != expected_nonce:
        raise ValueError("bootstrap nonce mismatch")
    certificate_der = _unb64(payload["certificate_der"])
    certificate_sha256 = _unb64(payload["certificate_sha256"])
    if certificate_sha256 != hashlib.sha256(certificate_der).digest():
        raise ValueError("bootstrap certificate hash mismatch")
    return {
        "nonce": nonce,
        "certificate_der": certificate_der,
        "certificate_sha256": certificate_sha256,
    }
