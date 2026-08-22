from __future__ import annotations

import asyncio

from appserve import WispContext
from appserve.client import _invoke_wisp_callback


def test_context_aware_state_callback_receives_authenticated_peer() -> None:
    seen: list[str] = []

    def state(context: WispContext) -> dict[str, str]:
        seen.append(context.peer_id)
        return {"peer": context.peer_id}

    result = asyncio.run(_invoke_wisp_callback(state, context=WispContext("android-uuid-a")))

    assert result == {"peer": "android-uuid-a"}
    assert seen == ["android-uuid-a"]


def test_context_aware_action_cannot_be_replaced_by_action_data() -> None:
    seen: list[str] = []

    def action(action_data: dict, context: WispContext) -> dict[str, str]:
        seen.append(context.peer_id)
        return {"value": action_data["value"], "peer": context.peer_id}

    result = asyncio.run(
        _invoke_wisp_callback(
            action,
            {"value": "ok", "peer_id": "forged"},
            context=WispContext("authenticated-peer-uuid"),
        )
    )

    assert result == {"value": "ok", "peer": "authenticated-peer-uuid"}
    assert seen == ["authenticated-peer-uuid"]


def test_legacy_callback_signature_remains_compatible_temporarily() -> None:
    result = asyncio.run(
        _invoke_wisp_callback(
            lambda action_data: {"value": action_data["value"]},
            {"value": "legacy"},
            context=WispContext("peer-uuid"),
        )
    )

    assert result == {"value": "legacy"}
