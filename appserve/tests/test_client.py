import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))

from appserve import Wisp, load


def test_wisp_manifest_and_load(tmp_path):
    config = {
        "server": "relay.example",
        "control_port": 443,
        "relay_port": 4443,
        "server_public_key": "AA==",
        "deployment_id": "private",
        "client_id": "prime-wisp",
    }
    path = tmp_path / "serverinfo.txt"
    path.write_text(json.dumps(config), encoding="utf-8")
    client = load(path)
    wisp = Wisp("prime", "Prime tester", "Tests numbers for primality", lambda: {"type": "html"}, lambda action: {"type": "html"})
    client.register(wisp)

    assert client.client_id == "prime-wisp"
    assert wisp.manifest()["id"] == "prime"
    assert client.info.host == "relay.example"


def test_state_request_does_not_call_action():
    calls = []
    wisp = Wisp(
        "prime", "Prime tester", "Tests numbers for primality",
        lambda: {"ui": "current"},
        lambda action: calls.append(action),
    )

    assert wisp.state() == {"ui": "current"}
    assert calls == []
