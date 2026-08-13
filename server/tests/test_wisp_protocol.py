import asyncio
import base64
import json
import time

from appserve_server.core import RelayConfig, RelayState, build_bootstrap
from appserve_server.service import RelayRuntime


def test_wisp_catalog_and_state_request_are_routed(tmp_path):
    async def scenario():
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        runtime = RelayRuntime(RelayConfig(pem), RelayState(tmp_path / "state.json"))
        control = await asyncio.start_server(runtime.handle_control, "127.0.0.1", 0)
        relay = await asyncio.start_server(runtime.handle_relay, "127.0.0.1", 0)
        try:
            cp = control.sockets[0].getsockname()[1]
            rp = relay.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", cp)
            bootstrap = build_bootstrap(runtime.config, {"client_id": "host", "client_public_key": "host", "timestamp": int(time.time())})
            writer.write(json.dumps({"type": "join", "payload": bootstrap.decode()}).encode() + b"\n")
            await writer.drain()
            joined = json.loads(await reader.readline())
            writer.write(json.dumps({"type": "wisps", "items": [{"id": "prime", "name": "Prime tester", "description": "test"}]}).encode() + b"\n")
            await writer.drain()
            assert json.loads(await reader.readline())["ok"] is True
            writer.close()
            await writer.wait_closed()
            assert runtime.state.wisps["prime"]["name"] == "Prime tester"

            reader, writer = await asyncio.open_connection("127.0.0.1", rp)
            writer.write(json.dumps({"type": "session", "session_token": joined["session_token"]}).encode() + b"\n")
            await writer.drain()
            assert json.loads(await reader.readline())["type"] == "ready"
            writer.write(json.dumps({"type": "envelope", "sender": "host", "recipient": "prime", "message_id": "m1", "ciphertext": "opaque", "body": {"action": "state_request", "wisp_id": "prime"}}).encode() + b"\n")
            await writer.drain()
            assert json.loads(await reader.readline())["type"] == "accepted"
            assert runtime.state.queues["prime"][0]["body"]["action"] == "state_request"
            writer.close()
            await writer.wait_closed()
        finally:
            control.close()
            relay.close()
            await control.wait_closed()
            await relay.wait_closed()

    asyncio.run(scenario())
