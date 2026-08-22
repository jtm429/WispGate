# WispGate architecture

WispGate is split into three runtime-owned layers:

- `server/appserve_server/`: TLS endpoint authentication, relay routing, durable registration, liveness, catalog publication, and bulk pairing.
- `appserve/`: Python Wisp runtime. It owns session decryption, operation lifecycle, file transfer, response assets, and callback dispatch.
- `wispgateclient/`: Android transport/runtime. It owns endpoint identity, session crypto, relay acknowledgements, catalog state, operations, and assets.

Applications register manifests and callbacks only. They do not implement TLS, endpoint authentication, relay frames, heartbeats, catalog updates, operation IDs, acknowledgements, or encrypted bulk transport.

The authenticated endpoint UUID is the only sender/recipient identity. Durable Wisp registration is separate from live relay liveness; reconnecting a relay endpoint causes a fresh catalog broadcast.
