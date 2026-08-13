import asyncio
import base64
import json
import time

from appserve_server.core import RelayConfig, RelayState, build_bootstrap
from appserve_server.service import RelayRuntime


def test_control_join_and_relay_forwarding(tmp_path):
    async def scenario():
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        runtime = RelayRuntime(RelayConfig(pem), RelayState(tmp_path / "state.json"))
        control = await asyncio.start_server(runtime.handle_control, "127.0.0.1", 0)
        relay = await asyncio.start_server(runtime.handle_relay, "127.0.0.1", 0)
        control_port = control.sockets[0].getsockname()[1]
        relay_port = relay.sockets[0].getsockname()[1]
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", control_port)
            payload = build_bootstrap(runtime.config, {
                "client_id": "sender",
                "client_public_key": "sender-key",
                "timestamp": int(time.time()),
            })
            writer.write(json.dumps({"type": "join", "payload": payload.decode()}).encode() + b"\n")
            await writer.drain()
            joined = json.loads(await reader.readline())
            writer.close()
            await writer.wait_closed()

            reader2, writer2 = await asyncio.open_connection("127.0.0.1", relay_port)
            writer2.write(json.dumps({"type": "session", "session_token": joined["session_token"]}).encode() + b"\n")
            await writer2.drain()
            assert json.loads(await reader2.readline())["type"] == "ready"
            writer2.write(json.dumps({
                "type": "envelope",
                "sender": "sender",
                "recipient": "recipient",
                "message_id": "m1",
                "ciphertext": "opaque",
            }).encode() + b"\n")
            await writer2.drain()
            assert json.loads(await reader2.readline())["type"] == "accepted"
            assert runtime.state.drain("recipient")[0]["ciphertext"] == "opaque"
            writer2.close()
            await writer2.wait_closed()
        finally:
            control.close()
            relay.close()
            await control.wait_closed()
            await relay.wait_closed()

    asyncio.run(scenario())
