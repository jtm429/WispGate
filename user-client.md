# User Client Specification

## Purpose

The user client is a generic native host and renderer. It owns the persistent connection to the relay, receives applet packages or applet responses, and displays the UI supplied by the webapp. It must not contain applet-specific UI, controls, workflows, or state transitions.

A user client is a trusted program in this private deployment. It is still responsible for keeping private keys and enforcing the small protocol boundary between a webapp and the operating system.

## Responsibilities

1. Load and validate `serverinfo.txt`.
2. Establish an outbound encrypted connection to the relay.
3. Authenticate using its client identity and a bootstrap message encrypted to the relay public key.
4. Maintain the connection with ping/pong, timeouts, and exponential-backoff reconnect.
5. Receive and verify applet manifests and bundles.
6. Cache bundles by content hash.
7. Start, stop, and display applets in an embedded WebView.
8. Expose the host bridge to the active webapp.
9. Encrypt all application envelopes end-to-end before sending them through the relay.
10. Route incoming envelopes to the correct applet or local service.

## Configuration

`serverinfo.txt` is a small text or JSON file distributed with an applet/program. The minimum fields are:

```json
{
  "server": "relay.example.net",
  "port": 443,
  "transport": "tls-websocket",
  "server_public_key": "base64url-ed25519-or-x25519-key",
  "deployment_id": "private-deployment-name"
}
```

The client must reject an invalid, missing, or changed server key unless the user explicitly replaces the configuration. A hostname alone is not sufficient server authentication.

## Connection lifecycle

```text
load config
  -> validate server key
  -> connect outbound
  -> bootstrap handshake
  -> authenticate client identity
  -> resume session / request applet catalog
  -> receive events and bundles
  -> reconnect on failure
```

The connection is persistent while the client is active. Reconnection is expected; connection IDs and message IDs make retries safe.

The relay may be deliberately offline because its Azure VM is stopped. This is not treated as a protocol failure. The client should:

- show an offline/disconnected state without treating it as data loss;
- retry with exponential backoff and jitter;
- reconnect promptly after the relay becomes reachable;
- re-authenticate after every new TCP/TLS connection;
- resume from the last acknowledged message ID where the server has retained state;
- avoid busy-looping while the VM is powered off.

The relay also attempts to reconnect to previously connected clients when it starts. The client should therefore retain enough local identity and resume state to accept a relay-start reconnect, perform a fresh authenticated handshake, and continue interrupted sessions. Relay-side reconnect attempts are best-effort; the client-side reconnect loop remains authoritative because clients may be asleep or behind a changed NAT mapping.

The client must not assume that an offline queue survived a VM shutdown unless the relay advertises durable queue storage. Application programs should retain important unsent data locally and retry it after reconnect.

## Turn-based applet model

An applet interaction is a sequence of responses and user actions:

```text
applet response R0 -> user client renders R0
user action A1     -> user client sends A1
applet response R1 -> user client renders R1
user action A2     -> user client sends A2
```

The user client does not infer application state. If it receives no new applet response, it leaves the current response/UI unchanged. The applet service is responsible for deciding what the next complete UI should be after each action.

An action may be a button click, form submission, selection, keyboard event, navigation request, or another generic event defined by the webapp. The protocol does not impose a fixed input schema.

## WebView model

The client loads an applet bundle from local memory or cache. It does not navigate the WebView to an arbitrary remote applet URL. The host supplies the applet's HTML, CSS, JavaScript, and declared metadata.

The WebView receives a generated local origin such as:

```text
appserve://applet/<applet-id>/<version>/
```

The applet should not be able to navigate outside its assigned local origin without an explicit host action.

## Generic host bridge

The bridge is deliberately generic. It carries lifecycle information and user-generated events; it does not encode applet-specific commands or widgets. Initial methods:

```text
appserve.ready()
appserve.identity()
appserve.send_action(action)
appserve.request_state()
appserve.close()
```

Bridge calls are request/response messages with IDs. Payloads are applet-defined JSON values or binary blobs referenced by content hash. The host may add generic capabilities later without changing the relay protocol.

## Local trust

Applets in this private deployment are authored by the same user, but the host still records the applet ID, version, and requested capabilities. This gives future programs a stable contract and avoids making the WebView an accidental unrestricted native shell.
