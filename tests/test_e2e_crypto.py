from __future__ import annotations

import copy

import pytest

from appserve.e2e import (
    E2E_ALGORITHM,
    decrypt_envelope,
    generate_identity,
    public_key_text,
    encrypt_envelope,
)


def test_application_payload_is_only_present_as_authenticated_ciphertext() -> None:
    android = generate_identity()
    wisp = generate_identity()
    body = {"wisp_id": "prime", "action": "state_request", "secret": "not for relay"}

    envelope = encrypt_envelope(
        sender="android-user",
        recipient="prime-wisp",
        message_id="message-1",
        body=body,
        recipient_public_key=public_key_text(wisp),
        sender_private_key=android,
        advertise_sender_key=True,
    )

    assert envelope["algorithm"] == E2E_ALGORITHM
    assert "body" not in envelope
    assert "not for relay" not in str(envelope)
    assert envelope["sender_public_key"] == public_key_text(android)
    decrypted, sender_key = decrypt_envelope(envelope, wisp)
    assert decrypted == body
    assert sender_key == public_key_text(android)


def test_known_sender_key_authenticates_later_envelopes_without_readvertising_it() -> None:
    android = generate_identity()
    wisp = generate_identity()
    envelope = encrypt_envelope(
        sender="prime-wisp",
        recipient="android-user",
        message_id="message-2",
        body={"wisp_id": "prime", "response": {"html": "<p>private</p>"}},
        recipient_public_key=public_key_text(android),
        sender_private_key=wisp,
        advertise_sender_key=False,
    )

    assert "sender_public_key" not in envelope
    body, sender_key = decrypt_envelope(envelope, android, public_key_text(wisp))
    assert body["response"]["html"] == "<p>private</p>"
    assert sender_key == public_key_text(wisp)


def test_tampering_is_rejected() -> None:
    android = generate_identity()
    wisp = generate_identity()
    envelope = encrypt_envelope(
        sender="android-user",
        recipient="prime-wisp",
        message_id="message-3",
        body={"action": "state_request"},
        recipient_public_key=public_key_text(wisp),
        sender_private_key=android,
        advertise_sender_key=True,
    )
    tampered = copy.deepcopy(envelope)
    tampered["sender"] = "somebody-else"

    with pytest.raises(ValueError, match="signature"):
        decrypt_envelope(tampered, wisp)
