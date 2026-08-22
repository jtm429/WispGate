# Application frames

The runtime unwraps the encrypted body and invokes the registered Wisp with application data plus trusted context:

```python
await wisp.action(action_data, WispContext(peer_id=authenticated_sender_uuid))
```

A state callback receives `WispContext`. Legacy `state()` / `action(action_data)` callbacks are compatibility-only and must not derive identity from action data.

A Wisp may maintain `state_by_peer[context.peer_id]`; a `peer_id` field inside user action data is untrusted and cannot replace the runtime context.
