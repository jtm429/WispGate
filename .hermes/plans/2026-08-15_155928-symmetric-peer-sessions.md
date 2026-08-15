# Symmetric Peer Sessions Implementation Plan

> **For Hermes:** Implement this plan in a dedicated Git worktree using strict TDD; do not modify or discard the existing uncommitted bulk-transfer work in the main checkout.

**Goal:** Preserve Android and Wisp long-term RSA identity keys, use RSA only to mutually authenticate a short-lived peer session, and encrypt ordinary turn-based JSON messages with directional AES-256-GCM keys for an absolute maximum of 30 minutes.

**Architecture:** The first interaction between an endpoint pair uses the existing RSA-OAEP/AES-GCM/RSA-PSS envelope to exchange a random 32-byte session master secret and a challenge-bound acceptance. Both endpoints derive independent Android→Wisp and Wisp→Android AES keys with HKDF-SHA256. Subsequent actions and responses use compact `session_envelope` frames with authenticated routing metadata, directional sequence counters, and deterministic 96-bit nonces. The relay routes these frames opaquely but never receives session secrets. Existing long-term endpoint keys and TOFU pinning remain the identity boundary.

**Tech Stack:** Python 3.11, `cryptography`, Kotlin/JVM, Android Keystore, JUnit, pytest, asyncio JSON-line relay.

---

## Fixed protocol decisions

1. Long-term RSA keypairs remain persistent on Android and Wisp hosts.
2. Session scope is one authenticated endpoint pair (`android-user` ↔ Wisp owner), not one individual Wisp UI.
3. Session maximum lifetime is 30 minutes from creation; traffic does not extend it indefinitely.
4. A session is discarded on peer-key substitution, authentication failure, sequence failure, explicit close, or process restart. Re-establishment is automatic on the next action.
5. Use independent HKDF-SHA256 outputs labelled `wispgate-session-v1/android-to-wisp` and `wispgate-session-v1/wisp-to-android`.
6. Each direction starts at sequence zero. A 96-bit AES-GCM nonce is a fixed four-byte protocol prefix plus the unsigned 64-bit sequence number. Never reuse a sequence under one directional key.
7. Authenticate `version`, `type`, `session_id`, `sender`, `recipient`, and `sequence` as canonical JSON AAD.
8. The relay acceptance remains transport-only. Endpoint AEAD verification is authoritative.
9. Do not add a legacy compatibility branch. Update Android, Python, relay, tests, and protocol documentation coherently.
10. Keep the in-progress dedicated bulk-transfer implementation separate. Bulk file ciphertext/key handling is not redesigned in this task; its control messages should be able to travel inside a symmetric session once both branches are reconciled.
11. Proactive/offline Wisp alerts are future work. This implementation must not remove Android’s public/private identity or prevent a Wisp from initiating a new RSA-authenticated session later.

---

### Task 1: Isolate the implementation from bulk-transfer work

**Objective:** Create a dedicated worktree and establish a clean baseline without touching the main checkout’s uncommitted files.

**Files:**
- Worktree: `C:/Users/E1111735/Documents/programming/appletserver-session-keys`
- Base revision: `e3f207a`

**Steps:**
1. Confirm `e3f207a` exists and inspect the main checkout status without modifying it.
2. Create branch `feature/symmetric-peer-sessions` and the dedicated worktree from `e3f207a`.
3. Run the existing Python tests and focused Android unit tests in the worktree to establish baseline behavior.
4. Record any baseline failure exactly; do not “fix” unrelated failures.

---

### Task 2: Define cross-language session derivation fixtures

**Objective:** Establish one deterministic cryptographic contract shared by Python and Android.

**Files:**
- Modify: `appserve/e2e.py`
- Modify: `tests/test_python_client_e2e.py` or create `tests/test_session_crypto.py`
- Modify: `wispgateclient/app/src/main/java/com/example/wispgateclient/E2EEnvelope.kt` or create `SessionCrypto.kt`
- Modify/create: `wispgateclient/app/src/test/java/com/example/wispgateclient/SessionCryptoTest.kt`

**RED:**
1. Add a Python test with fixed master secret, session ID, endpoint IDs, direction, sequence, plaintext, and expected derived keys/nonce/AAD/ciphertext.
2. Add the same fixture to Kotlin and assert byte-for-byte parity.
3. Run each focused test and confirm failure because session crypto does not exist.

**GREEN:**
1. Implement HKDF-SHA256 directional key derivation.
2. Implement canonical AAD construction.
3. Implement nonce derivation with overflow rejection.
4. Implement AES-256-GCM encrypt/decrypt helpers.
5. Reject wrong sender, recipient, session ID, direction, sequence, tag, and expired-session use.
6. Run focused Python and Android tests to green.

---

### Task 3: Add authenticated session state and lifecycle in Python

**Objective:** Let the Wisp runtime accept one RSA-authenticated session establishment and then process compact symmetric messages.

**Files:**
- Modify: `appserve/client.py`
- Modify: `appserve/e2e.py`
- Test: `tests/test_python_client_e2e.py`

**RED vertical slices:**
1. Test that `session_init` inside a valid existing RSA envelope creates a peer session only after Android’s signature and pinned public key are verified.
2. Test that the Wisp returns a challenge-bound `session_accept` proving possession of the new master secret and its long-term identity.
3. Test that a valid `session_envelope` decrypts and reaches `state_request`/`user_action` without any per-message RSA unwrap or signature.
4. Test independent inbound/outbound sequence counters.
5. Test rejection of replay, skipped/out-of-order sequence, altered routing metadata, wrong AEAD tag, wrong peer, unknown session, and session older than 30 minutes.
6. Test automatic cleanup on close and process lifecycle.

**GREEN:**
1. Add a small peer-session record containing IDs, keys, counters, creation deadline, and session ID.
2. Route existing RSA envelopes only for session establishment when no active session exists.
3. Route `session_envelope` frames through session verification before dispatching the existing Wisp action/state logic.
4. Encrypt normal Wisp responses with the active Wisp→Android session key.
5. Keep file/bulk application bodies generic so the bulk branch can be reconciled later.

---

### Task 4: Teach the relay to route compact session envelopes

**Objective:** Allow the relay to forward symmetric frames without learning or validating their plaintext.

**Files:**
- Modify: `server/appserve_server/service.py`
- Test: `tests/test_relay_e2e_boundary.py`

**RED:**
1. Test that an authenticated sender can forward a `session_envelope` containing only routing/session metadata plus ciphertext/tag.
2. Test that sender spoofing, missing fields, extra plaintext body, invalid recipient, or oversized frames are rejected.
3. Test that the relay sends `accepted` before forwarding, preserving current response ordering.
4. Test `recipient_offline` for session frames.
5. Assert the relay never receives a session master secret or decrypted action body.

**GREEN:**
1. Add an explicit schema branch for `session_envelope` rather than weakening existing RSA-envelope validation.
2. Reuse the existing destination lookup and acceptance-before-forwarding ordering.
3. Keep relay framing bounded and opaque.

---

### Task 5: Establish and cache sessions on Android

**Objective:** Make Android automatically establish a session for a Wisp owner and reuse it for subsequent actions for at most 30 minutes.

**Files:**
- Create: `wispgateclient/app/src/main/java/com/example/wispgateclient/SessionCrypto.kt`
- Modify: `wispgateclient/app/src/main/java/com/example/wispgateclient/RelayClient.kt`
- Modify: `wispgateclient/app/src/main/java/com/example/wispgateclient/E2EEnvelope.kt` only where handshake support belongs
- Test: `wispgateclient/app/src/test/java/com/example/wispgateclient/SessionCryptoTest.kt`
- Test: appropriate RelayClient-focused JVM tests or extracted protocol tests

**RED vertical slices:**
1. First state request sends one RSA-authenticated `session_init`, verifies `session_accept`, then sends the state request symmetrically.
2. A second action within 30 minutes sends no RSA-wrapped application envelope.
3. Android uses separate send/receive keys and counters.
4. Expired/unknown/rejected sessions are discarded and transparently re-established once.
5. Replay, sequence mismatch, wrong peer, altered header, and bad tag fail closed.
6. Parallel actions remain serialized and cannot reuse a sequence.

**GREEN:**
1. Add an in-memory session cache keyed by Wisp owner and pinned peer-key fingerprint.
2. Generate a random master secret/session ID/challenge for the handshake.
3. Keep the existing RSA identity envelope only for `session_init`/`session_accept`.
4. Replace ordinary `state_request`, `user_action`, and resulting response frames with `session_envelope`.
5. Do not persist raw session secrets across app process restarts in this version.

---

### Task 6: Cross-language encrypted integration tests

**Objective:** Prove the actual Android/Python wire contract and turn-based behavior.

**Files:**
- Modify/create: `tests/test_session_protocol_e2e.py`
- Modify: Android session fixture tests as necessary

**RED/GREEN slices:**
1. Use a fixed fixture produced by one language and consumed by the other in each direction.
2. Prove first request incurs handshake and subsequent action does not contain `encrypted_key` or `signature`.
3. Prove Wisp response uses the opposite directional key and expected sequence.
4. Prove a 30-minute expiration requires a new session ID and keys.
5. Prove two different Android identity keys produce independently authenticated sessions and cannot impersonate each other.

---

### Task 7: Reconcile with dedicated bulk transport

**Objective:** Integrate the completed session branch with the separately developed bulk-transfer branch without losing either feature.

**Files likely to overlap:**
- `appserve/client.py`
- `server/appserve_server/service.py`
- `tests/test_python_client_e2e.py`
- `tests/test_relay_e2e_boundary.py`
- `wispgateclient/app/src/main/java/com/example/wispgateclient/RelayClient.kt`
- `wispgateclient/app/src/main/java/com/example/wispgateclient/BulkFileCrypto.kt`
- `wispgateclient/app/src/test/java/com/example/wispgateclient/WispFileTransferTest.kt`

**Steps:**
1. Do not perform this merge while the main checkout has unknown/uncommitted bulk changes.
2. Return a clean session-feature commit and list exact overlap/conflict points.
3. Parent agent inspects and verifies the bulk branch first.
4. Merge/cherry-pick session work into the combined branch.
5. Ensure bulk negotiation (`file_begin`, readiness, final Wisp response) travels as symmetric session application bodies while raw ciphertext remains on the bulk socket.
6. Resolve conflicts semantically, never by choosing one entire side of an overlapping file.

---

### Task 8: Documentation and one consolidated verification

**Objective:** Document and verify the coherent final protocol.

**Files:**
- Modify: `protocol.md`

**Documentation must explain:**
- long-term RSA identity versus short-lived symmetric sessions;
- handshake messages;
- 30-minute absolute lifetime;
- directional keys and sequence counters;
- relay-visible versus E2E-hidden fields;
- active-session Wisp push capability and future offline initiation;
- bulk control messages versus raw bulk ciphertext;
- no compatibility/version-negotiation branch.

**Verification after reconciliation:**
1. Run the complete Python suite once.
2. Run Android unit tests and `assembleDebug` once using Android Studio’s JDK and bounded Gradle settings.
3. Run `git diff --check`.
4. Install the standard debug APK to the connected Android device if available.
5. Exercise two real actions against one live Wisp and verify logs show one RSA handshake followed by symmetric frames.
6. Exercise one real bulk upload after the bulk branch is available.
7. Check current-attempt Android and Wisp logs for cryptographic, sequence, lifecycle, and socket failures.
8. Commit/push only after the combined tree passes; report source, deployment, and physical runtime evidence separately.

---

## Risks and tradeoffs

- **No forward secrecy in the minimal RSA-wrapped master-secret handshake:** compromise of a Wisp RSA private key could decrypt recorded handshakes. A later signed ephemeral X25519 handshake can add forward secrecy without changing the symmetric message layer.
- **Clock handling:** use monotonic elapsed time for local expiration; do not trust peer wall-clock timestamps for session validity.
- **Sequence persistence:** because session secrets are not persisted, process restart safely creates a new session rather than risking nonce reuse.
- **Multiple Wisp IDs per owner:** share one endpoint session but keep `wisp_id` inside the encrypted application body.
- **Concurrency:** serialize outbound session sequence assignment and inbound verification atomically.
- **Relay metadata:** sender, recipient, session ID, timing, and ciphertext length remain visible to the relay; application bodies and keys do not.
- **Offline proactive alerts:** retain Android’s identity key now, but defer opaque queued session-init/notification design until alerts are implemented.

## Completion criteria

- Only handshake traffic performs RSA operations.
- At least two consecutive ordinary actions use the same unexpired symmetric session.
- Android and Wisp mutually authenticate their persistent identities during establishment.
- Directional AES-GCM keys, deterministic nonces, and strict sequences interoperate across Kotlin and Python.
- Sessions expire after at most 30 minutes and safely re-establish.
- Relay remains unable to decrypt application content.
- Existing turn-based Wisp behavior remains unchanged.
- Combined bulk-transfer work still functions after semantic reconciliation.
