from __future__ import annotations

import base64
import hmac
import json
import os
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

E2E_ALGORITHM = "RSA-OAEP-256+A256GCM+PS256"
SESSION_LIFETIME_SECONDS = 30 * 60
_SESSION_NONCE_PREFIX = b"WG\x01\x00"
_ANDROID_TO_WISP = b"wispgate-session-v1/android-to-wisp"
_WISP_TO_ANDROID = b"wispgate-session-v1/wisp-to-android"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def derive_session_keys(master_secret: bytes, session_id: str) -> tuple[bytes, bytes]:
    if len(master_secret) != 32 or not session_id:
        raise ValueError("session master secret and id are required")
    def derive(label: bytes) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(), length=32, salt=session_id.encode("utf-8"), info=label
        ).derive(master_secret)
    return derive(_ANDROID_TO_WISP), derive(_WISP_TO_ANDROID)


def session_accept_proof(master_secret: bytes, session_id: str, challenge: str, android_id: str, wisp_id: str) -> str:
    _, wisp_key = derive_session_keys(master_secret, session_id)
    transcript = b"\0".join([
        b"wispgate-session-v1/accept", session_id.encode(), challenge.encode(), android_id.encode(), wisp_id.encode()
    ])
    return _b64(hmac.digest(wisp_key, transcript, "sha256"))


def session_nonce(sequence: int) -> bytes:
    if not isinstance(sequence, int) or isinstance(sequence, bool) or not 0 <= sequence < (1 << 64):
        raise ValueError("invalid session sequence")
    return _SESSION_NONCE_PREFIX + sequence.to_bytes(8, "big")


def session_aad(session_id: str, sender: str, recipient: str, sequence: int) -> bytes:
    return json.dumps(
        {
            "version": 1,
            "type": "session_envelope",
            "session_id": session_id,
            "sender": sender,
            "recipient": recipient,
            "sequence": sequence,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


class PeerSession:
    """In-memory directional session state; secrets are deliberately never persisted."""

    def __init__(
        self,
        session_id: str,
        local_id: str,
        peer_id: str,
        android_to_wisp_key: bytes,
        wisp_to_android_key: bytes,
        *,
        created_at: float,
        android_side: bool,
    ) -> None:
        self.session_id = session_id
        self.local_id = local_id
        self.peer_id = peer_id
        self.created_at = created_at
        self.send_sequence = 0
        self.receive_sequence = 0
        is_android_side = android_side
        self._send_key = android_to_wisp_key if is_android_side else wisp_to_android_key
        self._receive_key = wisp_to_android_key if is_android_side else android_to_wisp_key

    def _check_live(self, now: float) -> None:
        if now >= self.created_at + SESSION_LIFETIME_SECONDS:
            raise ValueError("session expired")

    def bulk_key(self, transfer_id: str, *, sending: bool) -> bytes:
        if not isinstance(transfer_id, str) or not transfer_id:
            raise ValueError("bulk transfer id is required")
        return HKDF(
            algorithm=hashes.SHA256(), length=32, salt=transfer_id.encode("utf-8"),
            info=b"wispgate-bulk-v2",
        ).derive(self._send_key if sending else self._receive_key)

    def encrypt(self, body: dict[str, Any], *, now: float) -> dict[str, Any]:
        self._check_live(now)
        sequence = self.send_sequence
        envelope: dict[str, Any] = {
            "version": 1,
            "type": "session_envelope",
            "session_id": self.session_id,
            "sender": self.local_id,
            "recipient": self.peer_id,
            "sequence": sequence,
        }
        plaintext = json.dumps(body, separators=(",", ":")).encode("utf-8")
        envelope["ciphertext"] = _b64(
            AESGCM(self._send_key).encrypt(
                session_nonce(sequence), plaintext,
                session_aad(self.session_id, self.local_id, self.peer_id, sequence),
            )
        )
        self.send_sequence += 1
        return envelope

    def decrypt(self, envelope: dict[str, Any], *, now: float) -> dict[str, Any]:
        self._check_live(now)
        if (
            envelope.get("version") != 1
            or envelope.get("type") != "session_envelope"
            or envelope.get("session_id") != self.session_id
            or envelope.get("sender") != self.peer_id
            or envelope.get("recipient") != self.local_id
        ):
            raise ValueError("invalid session route")
        sequence = envelope.get("sequence")
        if sequence != self.receive_sequence:
            raise ValueError("invalid session sequence")
        plaintext = AESGCM(self._receive_key).decrypt(
            session_nonce(sequence),
            _unb64(envelope["ciphertext"]),
            session_aad(self.session_id, self.peer_id, self.local_id, sequence),
        )
        body = json.loads(plaintext)
        if not isinstance(body, dict):
            raise ValueError("session body must be an object")
        self.receive_sequence += 1
        return body


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
