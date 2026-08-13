import asyncio
import base64
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "server"))

from appserve import AppserveClient, ServerInfo
from appserve_server.core import RelayConfig, RelayState, build_bootstrap
from appserve_server.service import RelayRuntime


def test_real_wisp_client_handles_state_request_and_action(tmp_path):
    async def scenario():
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        config = RelayConfig(private)
        runtime = RelayRuntime(config, RelayState(tmp_path / "state.json"))
        control = await asyncio.start_server(runtime.handle_control, "127.0.0.1", 0)
        relay = await asyncio.start_server(runtime.handle_relay, "127.0.0.1", 0)
        try:
            control_port = control.sockets[0].getsockname()[1]
            relay_port = relay.sockets[0].getsockname()[1]
            client = AppserveClient(
                ServerInfo("127.0.0.1", control_port, relay_port, key.public_key().public_bytes(
                    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
                )),
                "prime-wisp",
            )
            current = {"html": "initial"}
            calls = []

            def state():
                return current.copy()

            def action(value):
                calls.append(value)
                current["html"] = f"result:{value['number']}"
                return current.copy()

            from appserve import Wisp
            client.register(Wisp("prime", "Prime", "A test", state, action))
            task = asyncio.create_task(client.serve())
            for _ in range(100):
                if "prime-wisp" in runtime.sessions:
                    break
                await asyncio.sleep(0.01)
            assert "prime-wisp" in runtime.sessions

            bootstrap_reader, bootstrap_writer = await asyncio.open_connection("127.0.0.1", control_port)
            bootstrap = build_bootstrap(config, {"client_id": "user", "client_public_key": "user"})
            bootstrap_writer.write((json.dumps({"type": "join", "payload": bootstrap.decode()}) + "\n").encode())
            await bootstrap_writer.drain()
            user_joined = json.loads(await bootstrap_reader.readline())
            bootstrap_writer.close()
            await bootstrap_writer.wait_closed()

            user_reader, user_writer = await asyncio.open_connection("127.0.0.1", relay_port)
            token = user_joined["session_token"]
            user_writer.write((json.dumps({"type": "session", "session_token": token}) + "\n").encode())
            await user_writer.drain()
            assert json.loads(await user_reader.readline())["type"] == "ready"

            def envelope(body):
                return {"type": "envelope", "sender": "user", "recipient": "prime-wisp", "message_id": "m", "ciphertext": "opaque", "body": body}

            user_writer.write((json.dumps(envelope({"wisp_id": "prime", "action": "state_request"})) + "\n").encode())
            await user_writer.drain()
            assert json.loads(await user_reader.readline())["type"] == "accepted"
            state_response = json.loads(await user_reader.readline())
            assert state_response["body"]["response"] == {"html": "initial"}
            assert calls == []

            user_writer.write((json.dumps(envelope({"wisp_id": "prime", "action": "user_action", "action_data": {"number": "7"}})) + "\n").encode())
            await user_writer.drain()
            assert json.loads(await user_reader.readline())["type"] == "accepted"
            action_response = json.loads(await user_reader.readline())
            assert action_response["body"]["response"] == {"html": "result:7"}
            assert calls == [{"number": "7"}]
            user_writer.close()
            await user_writer.wait_closed()
            client._writer.close()
            await client._writer.wait_closed()
            await asyncio.wait_for(task, timeout=1)
        finally:
            control.close()
            relay.close()
            await control.wait_closed()
            await relay.wait_closed()

    asyncio.run(scenario())
