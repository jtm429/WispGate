# Protocol and Security Specification

## Status

Version 1 uses explicit JSON message envelopes over relay sockets. Long-term RSA identities authenticate a one-time peer-session handshake; ordinary application payloads then use compact symmetric session envelopes. Endpoint runtimes encrypt all application data before it reaches the relay.

## Two encryption layers

1. **Transport encryption target**: TLS on both server ports. The current deployment still uses raw TCP, so TLS remains required before public deployment.
2. **Application end-to-end encryption**: the sender encrypts the application payload for the recipient before it reaches the relay. The relay forwards ciphertext and cannot decrypt it.

The relay's public bootstrap key is used only to protect the first join message. It is not the key used to encrypt every application payload.

## Version 1 cryptographic shape

- Client identity: persistent 3072-bit RSA key pair.
- RSA handshake-envelope payload encryption: fresh AES-256-GCM key and 96-bit nonce per envelope.
- Handshake content-key wrapping: RSA-OAEP with SHA-256 and MGF1-SHA-1, matching Android's standard OAEP provider behavior.
- Handshake sender authentication: RSA-PSS with SHA-256 and a 32-byte salt.
- Session payload encryption: AES-256-GCM under separate HKDF-SHA-256 keys for Android-to-Wisp and Wisp-to-Android traffic.
- Randomness: operating-system CSPRNG.
- Public-key bootstrap: a maintained hybrid-encryption implementation such as HPKE, if available for the selected language.

All binary fields use unpadded base64url. RSA-envelope authenticated routing metadata is canonical JSON containing `algorithm`, `message_id`, `recipient`, `sender`, `type`, and `version`. Session-envelope routing metadata is also AES-GCM additional authenticated data. The relay rejects envelopes containing a plaintext `body` field or any field outside the schema for that envelope type.

## Session establishment

The implemented peer handshake is:

```text
1. Each endpoint generates or loads a persistent 3072-bit RSA identity. Android retains its identity in the platform-backed endpoint identity store; the Python Wisp retains its identity beside its configuration. Both endpoints retain the peer RSA public key using trust on first use and reject substitutions.
2. Android creates a random 32-byte master secret, session ID, and challenge. It sends a signed RSA `envelope` whose encrypted body is `session_init` with those values and advertises its identity public key.
3. The Wisp verifies the RSA signature and pinned identity, decrypts the init, and derives two 32-byte keys with HKDF-SHA-256. The session ID bytes are the salt; the info labels are `wispgate-session-v1/android-to-wisp` and `wispgate-session-v1/wisp-to-android`.
4. The Wisp returns a signed RSA `envelope` containing `session_accept`, the session ID and challenge, and an HMAC-SHA-256 proof under the Wisp-to-Android key over the NUL-separated acceptance transcript.
5. Android verifies the Wisp's pinned RSA identity, route, challenge, session ID, proof, and handshake lifetime. Both sides then keep only the in-memory peer session for application traffic.
```

RSA identity keys remain the authentication root; session keys and master secrets are never persisted or exposed to the relay. A peer session has a 30-minute absolute lifetime measured from local establishment time. It is not extended by activity. Expiration, an unknown session, an invalid authentication tag, or an unexpected/replayed sequence invalidates that peer session. Android may invalidate and establish a fresh session once for the interrupted operation; ordinary application errors are not retried. A bad session frame is discarded by the Wisp without closing its persistent relay connection, so a fresh RSA handshake can follow on that connection.

After establishment, each application frame has only these relay-visible fields:

```json
{"version":1,"type":"session_envelope","session_id":"...","sender":"android-user","recipient":"prime-wisp","sequence":0,"ciphertext":"..."}
```

Each direction has its own key and monotonically increasing sequence starting at zero. The 96-bit AES-GCM nonce is the fixed four-byte prefix `57 47 01 00` followed by the unsigned 64-bit sequence in network byte order. The complete routing object (`version`, `type`, `session_id`, `sender`, `recipient`, and `sequence`) is canonical JSON AAD. Receivers require the exact next sequence, so missing, reordered, replayed, out-of-range, route-modified, or tag-modified frames fail closed.

If a recipient no longer has the referenced in-memory session, it sends an unencrypted relay-routed recovery control message:

```json
{"type":"session_reset","sender":"prime-wisp","recipient":"android-user","reason":"unknown_session"}
```

The relay validates and forwards this control message without treating it as application data. The sender invalidates its cached peer session, performs a fresh RSA session handshake, and retries the interrupted request once from the beginning. A reset never weakens long-term peer-key trust or silently accepts a changed identity.

## Transport heartbeat and transparent reanimation

Logical peer sessions and Wisp operations are independent of one physical relay TCP connection. Every long-lived control or relay connection uses TCP keepalive plus protocol heartbeat frames:

```json
{"type":"ping","nonce":"bounded-random-value"}
{"type":"pong","nonce":"bounded-random-value"}
```

These frames are relay-transport data, not end-to-end Wisp application data. The relay and endpoint runtimes consume them transparently, answer `ping` with the matching `pong`, and never expose them to a Wisp callback. Endpoints send heartbeats while a catalog subscription or operation owns the connection; the relay closes a connection that remains silent beyond the bounded heartbeat timeout. Application progress remains optional UX and is never required for liveness.

After a physical connection dies, an endpoint reconnects and authenticates automatically. It reuses an unexpired in-memory peer session only when its directional sequence state is still continuous; otherwise it performs a fresh identity-authenticated handshake. Long-running file actions use their stable transfer ID as an operation ID. The Python runtime keeps the operation alive across relay reconnects and retains its final response for a bounded period. Android can send the encrypted body below rather than upload or execute the operation again:

```json
{"wisp_id":"transcription-diarization","action":"operation_resume","operation_id":"stable-transfer-id"}
```

The Wisp runtime returns the retained completion, a `running` status, or an explicit `expired` status. Reconnection and heartbeat behavior belongs to the shared runtimes and relay; individual Wisps do not implement it.

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

The relay persists the catalog metadata and returns it to user clients during join. Each item carries its Wisp owner's public key so Android can authenticate and encrypt the peer-session handshake before sending application traffic. The user client can display the list without knowing anything about the Wisp's UI.

Selecting a Wisp establishes a peer session when one is not already live, then sends a generic, non-mutating state request:

```json
{
  "version": 1,
  "type": "session_envelope",
  "session_id": "...",
  "sender": "android-user",
  "recipient": "prime-wisp",
  "sequence": 0,
  "ciphertext": "..."
}
```

The ciphertext decrypts at the Wisp to `{"wisp_id":"prime","action":"state_request"}`. The preceding RSA session handshake advertises Android's public key; the Wisp pins that key on first use and rejects later substitutions. It responds with its current complete UI/state in the opposite-direction session envelope. This request must not advance the Wisp's turn or invoke its ordinary action handler. Other UI events use the same session and may advance the turn.

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

Reconnection never restores trust merely from an old relay session token. Long-term RSA identity trust is retained, but peer-session secrets are in-memory; after an endpoint reconnect they perform a new authenticated peer handshake.

Peer sessions are in-memory and are re-established after relay or endpoint reconnection. Shared file-action operations use stable transfer IDs and bounded completion retention so a reconnect resumes rather than repeats expensive work. Other mutating application actions still require a stable idempotency identity before they can be replayed automatically. A relay restart must not cause a client to treat a relay acceptance acknowledgement as proof that the recipient processed a frame.

## Message guarantees

Every symmetric application frame has:

- a peer-session ID;
- sender and recipient IDs;
- an absolute lifetime inherited from its in-memory session;
- an exact monotonically increasing directional sequence;
- authenticated ciphertext;

Receivers reject any sequence other than the exact next value. The relay's acknowledgement means only “accepted for forwarding”; it is not proof that the recipient authenticated or processed the frame.

## Key distribution

The relay distributes Wisp public keys in catalog entries. Android advertises its public key in each RSA `session_init` handshake. Both endpoints retain a trust-on-first-use record and reject a later key substitution. Public keys, session IDs, sequences, and routing metadata remain visible to the relay; master secrets, session keys, and decrypted application bodies do not.

## Threat model

After peer keys have been pinned, the design protects application contents from:

- a compromised relay server;
- relay database disclosure;
- network observers;
- a malicious relay forwarding, dropping, delaying, or replaying traffic.

It does not hide metadata such as connection timing, message sizes, routing IDs, or online status from the relay. It does not protect a client whose private keys or runtime are already compromised.

The initial catalog/refresh key exchange is trust-on-first-use. A relay already compromised before the first contact could substitute both endpoint keys. For protection against that first-contact attack, compare the endpoint fingerprints through an out-of-band trusted channel before accepting them.

## Generic file actions

File upload is a reusable WispGate action capability rather than an app-specific Android feature. A Wisp webapp may submit an ordinary HTML form with files through the host-injected runtime:

```html
<form id="upload">
  <input name="attachments" type="file" multiple>
  <input name="caption">
  <button>Send</button>
</form>
<script>
upload.addEventListener("submit", event => {
  event.preventDefault();
  WispGate.submitForm(upload, {type: "send"});
});
</script>
```

The runtime collects ordinary form values, stages selected browser `File` objects, and uses the established peer session for the encrypted control sequence:

```text
session_envelope(file_begin with manifests and one-time bulk tickets)
  <- session_envelope(ready with accepted transfer ID)
dedicated bulk TCP connection(s) carry opaque file ciphertext
  <- session_envelope(final complete/error and Wisp HTML response)
```

`file_begin`, Wisp readiness, and the final response are ordinary `session_envelope` control bodies. They do not fall back to per-message RSA envelopes. Each file uses a dedicated TCP connection to the bulk port, authenticated to the relay with the endpoint's relay session token and paired by a bounded one-time ticket from the encrypted manifest. A fresh per-file AES-256-GCM key is RSA-wrapped to the Wisp; the relay copies exactly the declared opaque ciphertext length and never receives plaintext file metadata or contents. Bulk ciphertext is therefore related to, but not carried inside, the symmetric peer-session stream. The Python runtime rejects malformed or duplicate manifests/tickets, undeclared lengths, incomplete authenticated ciphertext, more than 32 files, or more than 256 MiB in one action.

The existing Python action callback remains dictionary-compatible. File-aware callbacks inspect `action.files`; one file for a form field is an `UploadedFile`, while repeated files for one field are a tuple:

```python
from appserve import WispAction

def handle(action: WispAction):
    recording = action.files["recording"]
    with recording.open("rb") as source:
        process(source)
    # Use recording.save(destination) inside this callback to retain it.
    return {"html": "<p>Received.</p>"}
```

Temporary upload files are deleted after the action callback returns. Apps choose their form fields, accepted browser MIME types, semantic action values, and application-level limits; Android and the relay contain no collector-, audio-, document-, or image-specific branches.

## Generic Wisp response assets

A Wisp may attach files to a complete response without embedding their bytes in HTML or session JSON. The Wisp first sends an encrypted session body containing the complete response and one or more asset manifests:

```json
{
  "wisp_id": "qr-code",
  "response": {
    "content_type": "text/html",
    "html": "<img src=\"https://wisp.local/_wispgate/assets/qr-code\">"
  },
  "assets": {
    "type": "begin",
    "transfer_id": "...",
    "files": [{
      "id": "qr-code",
      "name": "qr.png",
      "content_type": "image/png",
      "size": 12345,
      "bulk": {
        "algorithm": "RSA-OAEP-256+A256GCM",
        "ticket": "...",
        "encrypted_key": "...",
        "nonce": "...",
        "ciphertext_size": 12361
      }
    }]
  }
}
```

After that session frame, the Wisp and Android open matching sender and receiver connections on the existing bulk relay. The relay's bounded ticket pairing allows either side to arrive first, so no separate readiness frame is required. Each asset uses a fresh AES-256-GCM key and nonce; the key is RSA-OAEP wrapped to Android. The authenticated bulk AAD is the NUL-separated sequence `wispgate-bulk-v1`, sender, recipient, transfer ID, asset ID, ticket, and plaintext size.

Android streams and authenticates each asset into app-private cache. After all bulk transfers complete, the Wisp sends:

```json
{"wisp_id":"qr-code","assets":{"type":"complete","transfer_id":"..."}}
```

Only after receiving and validating that completion does Android publish the response to the WebView. The WebView may request a declared asset at `https://wisp.local/_wispgate/assets/<asset-id>`; the native host intercepts that reserved route and streams the private cached file. Unknown asset IDs return a local error and never fall through to the network. Replacing or closing the Wisp response deletes its cached assets. IDs are restricted to URL-safe path-segment characters, and one response is bounded to 32 assets and 256 MiB total.

## Host-provided Wisp theme

The Android host injects its device-matched Wisp CSS into Wisp HTML before rendering. The host applies the current light/dark system mode and keeps the CSS locally on the device; it does not request a stylesheet over the relay.

A Wisp that wants to own its complete visual theme can opt out by including this metadata in its document:

```html
<meta name="wispgate-theme" content="custom">
```

The host then renders the Wisp HTML unchanged. The marker is a presentation preference only; it does not affect Wisp state, actions, or transport.

## Webapp boundary

The webapp is an interface authored by the user, not an untrusted public marketplace item. It still uses the host bridge instead of receiving raw private keys. The native host performs cryptographic operations and exposes only the applet messaging/storage operations needed by that applet.
