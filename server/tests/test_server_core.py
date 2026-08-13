import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from appserve_server.core import RelayConfig, RelayState, build_bootstrap, parse_bootstrap


def private_key_pem():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def test_bootstrap_round_trip_is_encrypted_and_recoverable():
    config = RelayConfig(server_private_key=private_key_pem())
    plaintext = build_bootstrap(
        config,
        {
            "deployment_id": "private",
            "client_id": "dashboard",
            "client_public_key": "client-key",
            "nonce": "n1",
            "timestamp": int(time.time()),
        },
    )

    assert b"dashboard" not in plaintext
    assert parse_bootstrap(config, plaintext)["client_id"] == "dashboard"


def test_relay_state_persists_clients_and_queues_opaque_messages(tmp_path):
    state = RelayState(tmp_path / "state.json", max_queue_per_client=2)
    state.register_client("dashboard", "client-key")
    state.queue("dashboard", {"message_id": "m1", "ciphertext": "opaque"})
    state.save()

    restored = RelayState(tmp_path / "state.json", max_queue_per_client=2)
    restored.load()

    assert restored.clients["dashboard"]["public_key"] == "client-key"
    assert restored.drain("dashboard")[0]["ciphertext"] == "opaque"


def test_relay_state_limits_offline_queue(tmp_path):
    state = RelayState(tmp_path / "state.json", max_queue_per_client=1)
    state.queue("dashboard", {"message_id": "m1"})
    state.queue("dashboard", {"message_id": "m2"})

    assert state.drain("dashboard") == [{"message_id": "m2"}]
