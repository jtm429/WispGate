# Wisp authoring

```python
from appserve import Wisp, WispContext

class MyWisp:
    def state(self, context: WispContext):
        return {"peer": context.peer_id}

    def action(self, action_data, context: WispContext):
        return {"ok": True}
```

Wisp authors do not implement TLS, endpoint authentication, AES session envelopes, heartbeats, catalog updates, operation IDs, relay acknowledgements, or encrypted file transfer. Never trust a peer ID supplied inside action data; use `context.peer_id`.
