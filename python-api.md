# Python API Sketch

This is the intended shape of the Python package. Names may change during implementation.

## Loading a private deployment

```python
import appserve

runtime = appserve.load("serverinfo.txt")
```

`load()` reads the server endpoint, pinned bootstrap public key, deployment ID, and local client identity configuration. It does not connect until `connect()` or an equivalent applet-runtime call is made.

## Native program endpoint

```python
async with runtime.connect(client_id="mailbox") as client:
    await client.publish(
        target="dashboard",
        channel="mailbox.events",
        payload={"type": "file_added", "name": "example.txt"},
    )

    async for message in client.subscribe("mailbox.commands"):
        await handle(message)
```

The package handles connection persistence, reconnect, authentication, envelope encryption, relay acknowledgements, and duplicate suppression.

Because the Azure relay may be powered off between sessions, `connect()` should not assume immediate availability. The runtime should expose connection state and retry automatically:

```python
async with runtime.connect(client_id="mailbox", reconnect=True) as client:
    async for state in client.status():
        print(state)  # connecting, online, offline, reconnecting
```

The exact status API is provisional. The important behavior is that starting the Azure VM causes the relay service to come up automatically, after which existing clients can reconnect without manual reconfiguration.

The relay also attempts to reconnect to clients that were previously registered with it. The runtime must accept this as a normal startup event, perform a fresh authenticated handshake, and restore subscriptions/resume state where possible.

## Webapp host

```python
app = runtime.applet(
    id="com.example.dashboard",
    bundle="dashboard.applet",
    capabilities=["publish", "subscribe", "notify"],
)

await appserve.run(app)
```

The native host loads the applet locally and injects the JavaScript bridge. Applet calls become encrypted application messages through the host.

## Design constraints

- `serverinfo.txt` is explicit and inspectable.
- The relay key is pinned, not discovered from an unauthenticated server response.
- Private keys remain local to each client.
- The relay never receives application plaintext.
- Applet payloads are application-defined; the protocol does not require typed inputs.
- Reconnect and offline delivery are built into the runtime rather than every applet.
