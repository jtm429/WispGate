# Applet Server

This directory defines a private, personal applet platform. It is not a public app marketplace and it is not a conventional website-hosting system.

The system has three roles:

- **User client**: the native host application used by Jacob. It maintains the long-lived service connection and renders webapp-supplied interfaces.
- **Webapp client**: an applet/webapp authored by the user. It defines the entire UI and receives user actions through the applet protocol.
- **Relay server**: a mostly blind rendezvous and message-relay service. It authenticates clients and forwards opaque encrypted envelopes.

The first implementation target is a Python module with an API shaped like:

```python
import appserve

appserve.load("serverinfo.txt")
```

`serverinfo.txt` contains the relay endpoint and the relay's public bootstrap key. It is an access/bootstrap code for this private deployment, not a claim of universal public trust.

## Documents

- [User client specification](user-client.md)
- [Webapp client specification](webapp-client.md)
- [Relay server specification](relay-server.md)
- [Protocol and security](protocol.md)
- [Python API sketch](python-api.md)

## Core model

```text
native user client ── persistent outbound connection ── relay server
       │                                                │
       └── local WebView/webapp                         └── opaque E2E ciphertext
```

The relay is hosted on Microsoft Azure and may be powered off when not in use to reduce cost. When the Azure VM starts, the relay service must start automatically as part of the machine boot process and begin accepting connections immediately. The relay is therefore an intermittently available service, not a permanently running dependency.

Clients initiate outbound connections when the relay is available. Neither client requires router port forwarding. When the relay is offline, clients use reconnect with backoff and resume automatically when it returns.

A webapp is delivered over the authenticated applet connection and loaded locally by the user client. It is not required to be fetched from a public HTTPS website. Applets are turn-based: after an applet response, the user client assumes that its state remains unchanged until another response arrives. UI actions are sent back as applet inputs.

## Deliberate scope

This is a private protocol for programs authored and operated by the same user. It does not attempt to solve public multi-tenant app distribution, hostile third-party applets, billing, or general plugin security. Nevertheless, the host bridge and message authentication are explicit so the design does not accidentally grant every webapp unrestricted native access.
