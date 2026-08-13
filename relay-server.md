# Relay Server Specification

## Purpose

The relay is a connection broker and opaque message forwarder. It does not render webapps, interpret application payloads, or need access to private program data.

The relay is deployed to a Microsoft Azure VM that may be stopped between sessions to control cost. Availability is expected to be intermittent. The relay process is a boot service: it must be enabled in the VM's startup configuration and start automatically as soon as the operating system is ready, without requiring an interactive login.

It accepts client connections on two ports:

- **Control port**: bootstrap, authentication, catalog, applet package delivery, health, and session management.
- **Relay port**: persistent application traffic and opaque end-to-end-encrypted envelopes.

The exact port numbers are deployment configuration; the initial conventional values may be `443` for control and `4443` for relay.

## Network behavior

Clients initiate outbound connections:

```text
user client  ──outbound──> control port
webapp host  ──outbound──> control port
              relay port
```

The server may push messages over either established connection. Clients do not need router port forwarding.

Both ports should use TLS in deployment. TLS protects the transport and client credentials; application payloads are encrypted separately so a compromised relay cannot read them.

## Startup and availability

The Azure VM deployment must provide:

- automatic relay startup on operating-system boot;
- automatic restart if the relay process exits unexpectedly;
- readiness only after both ports are bound and the server key/configuration are loaded;
- a lightweight health/readiness check for operational verification;
- persistent server identity and configuration outside the process working directory;
- persisted records of previously connected clients and their reconnect endpoints/session metadata;
- no dependence on an interactive desktop session.

The relay does not need to remain online continuously. Clients must treat connection failure as normal and retry with bounded exponential backoff. The server may optionally persist a bounded offline queue, but queued delivery is best-effort across a VM shutdown unless the queue is stored on durable Azure storage.

Starting the VM and starting the relay are separate operational actions. The intended deployment contract is:

```text
Azure VM starts
  -> operating system boots
  -> relay service starts automatically
  -> relay loads persistent keys/configuration
  -> control and relay ports become ready
  -> clients reconnect
```

When the relay starts, it restores its records of previously connected clients and actively attempts to re-establish those client connections. This is a relay-side reconnect attempt, not merely passive listening for new clients. The attempt may use the client's previously registered outbound connection address or an authenticated reconnect notification mechanism, depending on the transport and NAT state.

Because clients may be behind NAT, asleep, or no longer at the same network address, relay startup reconnect is best-effort. Clients must still implement their own reconnect loop. A client that receives a relay-start notification or sees the relay become reachable performs a fresh authenticated connection and resumes from its last acknowledged message ID.

## Bootstrap and join

A client loads `serverinfo.txt`, which contains the relay address and pinned relay public key. The first join message is an encrypted bootstrap envelope:

```text
client -> relay:
  encrypted_to_server_public_key(
    protocol_version,
    deployment_id,
    client_id,
    client_public_key,
    nonce,
    requested_role,
    timestamp
  )
```

The relay decrypts the bootstrap message with its private key, checks freshness and deployment ID, and establishes the authenticated session. It rejects plaintext join messages.

The relay public key is not intended to be a public directory key. It is a deployment secret/pinned bootstrap value distributed inside private programs and `serverinfo.txt`. Anyone who obtains it can encrypt a join request, but cannot decrypt existing traffic or impersonate a client without the client identity key.

## Client authentication

The relay stores the registered client public key or a deployment-specific client authorization record. A challenge/response proves possession of the client's private key. Client IDs are logical deployment identifiers, not human usernames.

After authentication, the relay assigns a connection ID and returns a session token bound to that connection. Session tokens expire and cannot replace the client identity key.

## Envelope forwarding

Application messages use an opaque envelope:

```json
{
  "version": 1,
  "message_id": "uuid",
  "sender": "client-a",
  "recipient": "client-b",
  "channel": "com.example.mailbox",
  "created_at": 0,
  "ciphertext": "base64url(...)"
}
```

The relay may inspect and validate routing fields, sizes, timestamps, and message IDs. It must treat `ciphertext` as opaque bytes and must not require application schemas.

It forwards envelopes to the recipient's active connection, queues a bounded amount when the recipient is offline, and returns delivery status only for relay acceptance. End-to-end processing acknowledgements are application messages.

## Applet delivery

The relay can deliver applet manifests and bundles to an authenticated user client. Bundle contents are either:

- signed by the private deployment's applet signing key; or
- authenticated by a pinned deployment hash/key in the private client.

The relay is not trusted to alter bundles. The user client verifies them before loading.

## Required server state

- registered client public keys;
- active connection table;
- bounded offline queue of opaque envelopes;
- applet manifest/package store or configured package source;
- replay/freshness records;
- audit logs containing metadata only.

Private identity keys, end-to-end session keys, and application plaintext must never be stored by the relay.

## Failure behavior

The relay should return explicit errors for:

```text
invalid_bootstrap
stale_bootstrap
unknown_client
bad_signature
unsupported_protocol
recipient_offline
queue_full
message_too_large
```

It should not reveal whether an application-level recipient or channel exists beyond the minimum routing response.
