# WispGate protocol

These documents are the normative wire-contract source for the Python runtime, Android runtime, and relay.

- [Transport](transport.md)
- [Identity and approval](identity-and-approval.md)
- [Relay sessions](relay-session.md)
- [Catalog and liveness](catalog.md)
- [Application frames](application.md)
- [Operations](operations.md)
- [File actions](file-actions.md)
- [Response assets](response-assets.md)
- [Errors](errors.md)

The protocol has no logical `android-user` identity. Every sender and recipient is an authenticated endpoint UUID.
