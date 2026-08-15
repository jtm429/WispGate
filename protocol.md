# Protocol and Security Specification

## Status

Version 1 uses explicit JSON message envelopes over persistent relay sockets. Application payloads are encrypted and signed by the endpoint runtimes before they are sent to the relay.

## Two encryption layers

1. **Transport encryption target**: TLS on both server ports. The current deployment still uses raw TCP, so TLS remains required before public deployment.
2. **Application end-to-end encryption**: the sender encrypts the application payload for the recipient before it reaches the relay. The relay forwards ciphertext and cannot decrypt it.

The relay's public bootstrap key is used only to protect the first join message. It is not the key used to encrypt every application payload.

## Version 1 cryptographic shape

- Client identity: persistent 3072-bit RSA key pair.
- Payload encryption: fresh AES-256-GCM key and 96-bit nonce per message.
- Content-key wrapping: RSA-OAEP with SHA-256 and MGF1-SHA-256.
- Sender authentication: RSA-PSS with SHA-256 and a 32-byte salt.
- Randomness: operating-system CSPRNG.
- Public-key bootstrap: a maintained hybrid-encryption implementation such as HPKE, if available for the selected language.

All binary fields use unpadded base64url. The authenticated routing metadata is canonical JSON containing `algorithm`, `message_id`, `recipient`, `sender`, `type`, and `version`. The relay rejects application envelopes containing a plaintext `body` field.

## Session establishment

For a first implementation:

```text
1. Client generates/loads a long-term identity key.
2. Client encrypts a fresh bootstrap payload to the pinned relay public key.
3. Relay decrypts it and sends a nonce challenge.
4. Client signs the challenge and transcript with its identity key.
5. Relay verifies the signature and returns a session record.
6. Clients establish or refresh a per-peer E2E session key.
```

The session transcript includes protocol version, deployment ID, both client IDs, and key fingerprints to prevent cross-deployment and downgrade confusion.

## Turn-based applet messages

Applet traffic is organized as alternating actions and responses rather than a continuously synchronized UI state:

```text
response(state_0, ui_0)
  -> action_1
response(state_1, ui_1)
  -> action_2
response(state_2, ui_2)
```

The user client is allowed to remain unchanged indefinitely after displaying a response. It changes the displayed applet only when the applet sends another response. The server and applet own the application state; the generic client does not hard-code or infer it.

An action is an applet-defined event payload. A response is an applet-defined complete UI/state payload. The protocol carries both as opaque encrypted application data and does not require typed inputs, fixed controls, or a standard widget vocabulary.

## Catalog and resend-state action

When a Wisp client joins, it registers its manifest:

```json
{
  "type": "wisps",
  "items": [{"id": "prime", "name": "Prime tester", "description": "...", "owner": "prime-wisp", "public_key": "base64url-DER"}]
}
```

The relay persists the catalog metadata and returns it to user clients during join. Each item carries its Wisp owner's public key so the Android endpoint can encrypt the first request before sending it. The user client can display the list without knowing anything about the Wisp's UI.

Selecting a Wisp sends a generic, non-mutating state request:

```json
{
  "version": 1,
  "type": "envelope",
  "sender": "android-user",
  "recipient": "prime-wisp",
  "message_id": "...",
  "algorithm": "RSA-OAEP-256+A256GCM+PS256",
  "encrypted_key": "...",
  "nonce": "...",
  "ciphertext": "...",
  "signature": "...",
  "sender_public_key": "base64url-DER"
}
```

The ciphertext decrypts at the Wisp to `{"wisp_id":"prime","action":"state_request"}`. The first refresh advertises Android's public key so the Wisp can authenticate the request and encrypt its response directly to Android. The Wisp pins that key on first use and rejects later substitutions. It responds with its current complete UI/state; this request must not advance the Wisp's turn or invoke its ordinary action handler. Other UI events are encrypted applet-defined actions and may advance the turn.

An Android host keeps its control connection open after catalog registration. When a Wisp registers or disconnects, the relay pushes:

```json
{"ok":true,"type":"catalog_update","items":[...]}
```

The host replaces its contacts from this message; it does not poll the relay for catalog changes. If an interactive request targets a Wisp with no active relay session, the relay returns `recipient_offline` immediately rather than acknowledging a request that cannot produce a response.

## Authenticated server update request

The Android host may send the fixed control message below after joining:

```json
{"type": "update_server"}
```

The request is accepted only after the Android client has completed the relay's authenticated join. The relay then starts the root-owned fixed update script. The update script accepts no user-supplied command or path; it fast-forwards the deployment checkout to `origin/main` and restarts the relay service. GitHub access remains separately restricted to the operator's VM credentials.

## Relay restart and client resumption

The relay persists client registration records and the information needed to attempt reconnection after an Azure VM restart. On startup it loads that state and tries to re-establish sessions with clients previously connected to the deployment.

Reconnection never restores trust merely from an old session token. Each client performs a fresh authenticated handshake using its identity key. Existing end-to-end keys may be resumed only if their local key-state rules permit it; otherwise the clients perform a new key exchange.

Message resumption uses acknowledged message IDs and application-level idempotency. A relay restart must not cause a client to treat a relay acceptance acknowledgement as proof that the recipient processed a message.

## Message guarantees

Every application message has:

- unique message ID;
- sender and recipient IDs;
- creation time and expiry;
- monotonically increasing sender sequence, where practical;
- authenticated ciphertext;
- optional reply-to ID.

Receivers deduplicate message IDs. Retries are safe. The relay's acknowledgement means only “accepted for forwarding/queueing.”

## Key distribution

The relay distributes Wisp public keys in catalog entries. Android includes its public key on each state-refresh envelope, including the first click. Both endpoints persist a trust-on-first-use record and reject a later key substitution. Public keys and routing metadata remain visible to the relay; decrypted application bodies do not.

## Threat model

After peer keys have been pinned, the design protects application contents from:

- a compromised relay server;
- relay database disclosure;
- network observers;
- a malicious relay forwarding, dropping, delaying, or replaying traffic.

It does not hide metadata such as connection timing, message sizes, routing IDs, or online status from the relay. It does not protect a client whose private keys or runtime are already compromised.

The initial catalog/refresh key exchange is trust-on-first-use. A relay already compromised before the first contact could substitute both endpoint keys. For protection against that first-contact attack, compare the endpoint fingerprints through an out-of-band trusted channel before accepting them.

## Host-provided Wisp theme

The Android host injects its device-matched Wisp CSS into Wisp HTML before rendering. The host applies the current light/dark system mode and keeps the CSS locally on the device; it does not request a stylesheet over the relay.

A Wisp that wants to own its complete visual theme can opt out by including this metadata in its document:

```html
<meta name="wispgate-theme" content="custom">
```

The host then renders the Wisp HTML unchanged. The marker is a presentation preference only; it does not affect Wisp state, actions, or transport.

## Webapp boundary

The webapp is an interface authored by the user, not an untrusted public marketplace item. It still uses the host bridge instead of receiving raw private keys. The native host performs cryptographic operations and exposes only the applet messaging/storage operations needed by that applet.
