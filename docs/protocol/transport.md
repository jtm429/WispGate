# Transport

Endpoints use JSON Lines over TLS. Each endpoint has a persistent UUID and RSA identity. The relay authenticates the endpoint UUID with a signed challenge before accepting application frames.

Relay routing is direct:

```python
destination = self.sessions.get(envelope["recipient"])
```

For an accepted forwarded frame, the sender receives the relay acknowledgement before the recipient receives the original encrypted frame. The acknowledgement means forwarding was accepted, not that the application completed.

Control and relay connections use heartbeat ping/pong. Heartbeats are transport liveness only; application progress is never a keepalive substitute.
