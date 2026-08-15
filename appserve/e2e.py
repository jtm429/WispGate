from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

E2E_ALGORITHM = "RSA-OAEP-256+A256GCM+PS256"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def generate_identity() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


def load_or_create_identity(path: str | Path) -> rsa.RSAPrivateKey:
    key_path = Path(path)
    if key_path.exists():
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise ValueError("WispGate identity key must be RSA")
        return key
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key = generate_identity()
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    os.chmod(key_path, 0o600)
    return key


def public_key_text(private_key: rsa.RSAPrivateKey) -> str:
    return _b64(
        private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def _public_key(value: str) -> rsa.RSAPublicKey:
    key = serialization.load_der_public_key(_unb64(value))
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("WispGate peer key must be RSA")
    return key


def _aad(envelope: dict[str, Any]) -> bytes:
    authenticated = {
        "version": envelope["version"],
        "type": envelope["type"],
        "sender": envelope["sender"],
        "recipient": envelope["recipient"],
        "message_id": envelope["message_id"],
        "algorithm": envelope["algorithm"],
    }
    return json.dumps(authenticated, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _signed_bytes(envelope: dict[str, Any]) -> bytes:
    return b"\0".join(
        [
            _aad(envelope),
            envelope["encrypted_key"].encode("ascii"),
            envelope["nonce"].encode("ascii"),
            envelope["ciphertext"].encode("ascii"),
        ]
    )


def encrypt_envelope(
    *,
    sender: str,
    recipient: str,
    message_id: str,
    body: dict[str, Any],
    recipient_public_key: str,
    sender_private_key: rsa.RSAPrivateKey,
    advertise_sender_key: bool = False,
) -> dict[str, Any]:
    envelope: dict[str, Any] = {
        "version": 1,
        "type": "envelope",
        "sender": sender,
        "recipient": recipient,
        "message_id": message_id,
        "algorithm": E2E_ALGORITHM,
    }
    content_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    plaintext = json.dumps(body, separators=(",", ":")).encode("utf-8")
    envelope["encrypted_key"] = _b64(
        _public_key(recipient_public_key).encrypt(
            content_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    )
    envelope["nonce"] = _b64(nonce)
    envelope["ciphertext"] = _b64(AESGCM(content_key).encrypt(nonce, plaintext, _aad(envelope)))
    if advertise_sender_key:
        envelope["sender_public_key"] = public_key_text(sender_private_key)
    envelope["signature"] = _b64(
        sender_private_key.sign(
            _signed_bytes(envelope),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
            hashes.SHA256(),
        )
    )
    return envelope


def decrypt_envelope(
    envelope: dict[str, Any],
    recipient_private_key: rsa.RSAPrivateKey,
    known_sender_public_key: str | None = None,
) -> tuple[dict[str, Any], str]:
    if envelope.get("algorithm") != E2E_ALGORITHM or envelope.get("type") != "envelope":
        raise ValueError("unsupported encrypted envelope")
    advertised = envelope.get("sender_public_key")
    if known_sender_public_key and advertised and advertised != known_sender_public_key:
        raise ValueError("peer public key changed")
    sender_public_key = known_sender_public_key or advertised
    if not sender_public_key:
        raise ValueError("sender public key required")
    try:
        _public_key(sender_public_key).verify(
            _unb64(envelope["signature"]),
            _signed_bytes(envelope),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
            hashes.SHA256(),
        )
    except InvalidSignature as exc:
        raise ValueError("invalid envelope signature") from exc
    content_key = recipient_private_key.decrypt(
        _unb64(envelope["encrypted_key"]),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    plaintext = AESGCM(content_key).decrypt(
        _unb64(envelope["nonce"]),
        _unb64(envelope["ciphertext"]),
        _aad(envelope),
    )
    body = json.loads(plaintext)
    if not isinstance(body, dict):
        raise ValueError("encrypted envelope body must be an object")
    return body, sender_public_key
