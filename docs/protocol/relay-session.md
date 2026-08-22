# Relay sessions

Session handshake:

```text
Android UUID A -> Wisp UUID W: RSA session_init
Wisp UUID W -> Android UUID A: RSA session_accept
A <-> W: AES-GCM session_envelope
```

The Android runtime constructs `PeerSession(localId=client_id, peerId=wisp_owner, androidSide=true)`. The Python runtime constructs the inverse role with `android_side=False`. AES direction is explicit; it is never inferred from a string identity.

The relay validates every encrypted frame with:

```python
sender == authenticated_transport_client_id
```
