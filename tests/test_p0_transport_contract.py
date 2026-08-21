from __future__ import annotations

import asyncio
import base64
import datetime
import hashlib
import json
import ssl
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from appserve.client import AppserveClient, ServerInfo
from appserve.e2e import generate_identity, public_key_text
from server.appserve_server.core import (
    RelayConfig,
    RelayState,
    build_bootstrap_request,
    decrypt_bootstrap_request,
    build_bootstrap_response,
    decrypt_bootstrap_response,
)
from server.appserve_server.service import RelayRuntime, create_server_ssl_context


def make_certificate(tmp_path: Path) -> tuple[Path, Path, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "tls-cert.pem"
    key_path = tmp_path / "tls-key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    fingerprint = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    return cert_path, key_path, fingerprint


def test_server_info_uses_relay_identity_bootstrap_without_manual_certificate_fingerprint() -> None:
    info = ServerInfo("localhost", 443, 4443, b"relay-public-key")
    assert not hasattr(info, "tls_cert_sha256")


def test_encrypted_bootstrap_binds_client_nonce_challenge_and_certificate_hash() -> None:
    relay = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    endpoint = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    nonce = b"client-fresh-nonce"
    request = build_bootstrap_request(relay.public_key(), "android-user", endpoint.public_key(), nonce)
    decoded = decrypt_bootstrap_request(relay, request)
    assert decoded["client_id"] == "android-user"
    assert decoded["client_public_key"].public_numbers() == endpoint.public_key().public_numbers()
    assert decoded["nonce"] == nonce

    response = build_bootstrap_response(
        endpoint.public_key(), nonce, b"certificate-der"
    )
    result = decrypt_bootstrap_response(endpoint, response, nonce)

    assert result["certificate_der"] == b"certificate-der"
    assert result["certificate_sha256"] == hashlib.sha256(b"certificate-der").digest()
    with pytest.raises(ValueError, match="nonce"):
        decrypt_bootstrap_response(endpoint, response, b"different-nonce")


def test_real_tls13_listener_accepts_pinned_client_and_rejects_plaintext(tmp_path: Path) -> None:
    cert_path, key_path, fingerprint = make_certificate(tmp_path)

    async def scenario() -> None:
        observed: list[bytes] = []

        async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            observed.append(await reader.readline())
            writer.write(b"ok\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(
            handler,
            "127.0.0.1",
            0,
            ssl=create_server_ssl_context(cert_path, key_path),
        )
        port = server.sockets[0].getsockname()[1]
        try:
            info = ServerInfo("127.0.0.1", port, port, b"unused", bulk_port=port)
            client = AppserveClient(info, "tls-test", identity_key=generate_identity())
            client._tls_anchor_sha256 = fingerprint
            reader, writer = await client._open_tls(port)
            assert writer.get_extra_info("ssl_object").version() == "TLSv1.3"
            writer.write(b"tls\n")
            await writer.drain()
            assert await reader.readline() == b"ok\n"
            writer.close()
            await writer.wait_closed()

            plain_reader, plain_writer = await asyncio.open_connection("127.0.0.1", port)
            plain_writer.write(b"plaintext\n")
            await plain_writer.drain()
            assert await asyncio.wait_for(plain_reader.read(), timeout=1) == b""
            plain_writer.close()
            await plain_writer.wait_closed()
        finally:
            server.close()
            await server.wait_closed()

        assert observed == [b"tls\n"]

    asyncio.run(scenario())


def sign_auth(identity, role: str, client_id: str, challenge: str, ticket: str = "", peer: str = "", length: str = "") -> str:
    transcript = f"wisp-relay-auth-v1\n{role}\n{client_id}\n{challenge}\n{ticket}\n{peer}\n{length}".encode("ascii")
    signature = identity.sign(
        transcript,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )
    return base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")


async def authenticate(
    port: int,
    identity,
    client_id: str,
    role: str = "relay",
    *,
    proof_challenge: str | None = None,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, dict]:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(json.dumps({
        "type": "auth_hello",
        "role": role,
        "client_id": client_id,
        "client_kind": "android",
        "public_key": public_key_text(identity),
    }).encode() + b"\n")
    await writer.drain()
    challenge = json.loads(await reader.readline())
    if challenge.get("type") != "auth_challenge":
        return reader, writer, challenge
    signed = proof_challenge or challenge["challenge"]
    writer.write(json.dumps({
        "type": "auth_proof",
        "signature": sign_auth(identity, role, client_id, signed),
    }).encode() + b"\n")
    await writer.drain()
    return reader, writer, json.loads(await reader.readline())


def test_relay_auth_enrolls_once_rejects_changed_key_and_consumes_challenge(tmp_path: Path) -> None:
    async def scenario() -> None:
        state = RelayState(tmp_path / "state.json")
        relay = RelayRuntime(RelayConfig(b"", enrollment_enabled=True), state)
        identity = generate_identity()
        changed = generate_identity()
        server = await asyncio.start_server(relay.handle_relay, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            reader, writer, result = await authenticate(port, identity, "endpoint")
            assert result == {"ok": True, "type": "authenticated", "client_id": "endpoint"}
            writer.close()
            await writer.wait_closed()
            enrolled = json.loads(state.path.read_text(encoding="utf-8"))
            assert enrolled["clients"]["endpoint"]["public_key"] == public_key_text(identity)
            assert "session_token" not in str(enrolled)

            _, changed_writer, changed_result = await authenticate(port, changed, "endpoint")
            assert changed_result == {"ok": False, "error": "endpoint_key_changed"}
            changed_writer.close()
            await changed_writer.wait_closed()

            first_reader, first_writer = await asyncio.open_connection("127.0.0.1", port)
            hello = {"type": "auth_hello", "role": "relay", "client_id": "endpoint", "public_key": public_key_text(identity)}
            first_writer.write(json.dumps(hello).encode() + b"\n")
            await first_writer.drain()
            old_challenge = json.loads(await first_reader.readline())["challenge"]
            first_writer.close()
            await first_writer.wait_closed()

            _, replay_writer, replay_result = await authenticate(
                port, identity, "endpoint", proof_challenge=old_challenge
            )
            assert replay_result == {"ok": False, "error": "invalid_auth_proof"}
            replay_writer.close()
            await replay_writer.wait_closed()
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(scenario())


def test_unknown_endpoint_is_rejected_when_enrollment_is_disabled(tmp_path: Path) -> None:
    async def scenario() -> None:
        relay = RelayRuntime(RelayConfig(b"", enrollment_enabled=False), RelayState(tmp_path / "state.json"))
        server = await asyncio.start_server(relay.handle_relay, "127.0.0.1", 0)
        try:
            port = server.sockets[0].getsockname()[1]
            _, writer, result = await authenticate(port, generate_identity(), "unknown")
            assert result == {"ok": False, "error": "unknown_endpoint"}
            writer.close()
            await writer.wait_closed()
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(scenario())
