# Implementing a WispGate Wisp in a Python Program

This guide explains how to add a WispGate interface to an existing Python program. It uses the API that currently exists in this repository.

A **Wisp** is the Python side of a small application. It owns:

- the program's state and logic;
- the HTML interface shown on Android;
- the actions that run when the user presses buttons or submits forms.

WispGate owns the generic plumbing:

- listing the Wisp in the Android client;
- opening the encrypted connection;
- rendering the HTML in a WebView;
- carrying actions to Python;
- returning the next complete interface to Android;
- reconnecting when the relay becomes available again.

The normal flow is:

```text
Python creates and registers a Wisp
        ↓
WispGate lists it in the Android client
        ↓
The user opens it
        ↓
Python's state() returns the current HTML
        ↓
The user performs an action in that HTML
        ↓
Python's action(...) updates the program and returns new HTML
```

## 1. Make the WispGate package importable

The reusable Python module is the `appserve` directory in this repository.

If your program is inside this repository, run it from the repository root or place its launcher under a directory such as `examples/`. Then Python can import the module normally:

```python
import appserve
```

If your program lives elsewhere, add this repository's root directory to your Python environment while WispGate is still used directly from source. For example, set `PYTHONPATH` to the repository root before launching the program.

The Python runtime also needs the `cryptography` package:

```bash
python -m pip install "cryptography>=43,<47"
```

What this step does: it makes the reusable WispGate classes and encryption code available to your program. It does not start a connection yet.

## 2. Create a Wisp class

Keep the application's own logic in an ordinary Python class. The class needs two important methods:

- `state()` returns the complete interface exactly as it currently should appear. It must not change the application's state.
- `action(payload)` receives an event from the interface, updates the application if necessary, and returns the next complete interface.

Here is a complete counter example:

```python
from __future__ import annotations

from appserve import Wisp


class CounterProgram:
    def __init__(self) -> None:
        self.count = 0

    def render(self) -> dict[str, str]:
        return {
            "content_type": "text/html",
            "html": f"""
                <main>
                  <h1>Count: {self.count}</h1>
                  <button onclick='WispGate.submit({{type: "increment"}})'>
                    Add one
                  </button>
                  <button onclick='WispGate.submit({{type: "reset"}})'>
                    Reset
                  </button>
                </main>
            """,
        }

    def state(self) -> dict[str, str]:
        # Merely describe the current screen. Do not advance the program here.
        return self.render()

    def action(self, payload: dict) -> dict[str, str]:
        if payload.get("type") == "increment":
            self.count += 1
        elif payload.get("type") == "reset":
            self.count = 0

        return self.render()

    def as_wisp(self) -> Wisp:
        return Wisp(
            id="counter",
            name="Counter",
            description="A small example counter",
            state=self.state,
            action=self.action,
        )
```

What this step does: it separates your application from the networking layer. `CounterProgram` does not open sockets or perform encryption. It only describes the UI and handles application events.

### The four Wisp fields

| Field | Purpose |
|---|---|
| `id` | A stable machine-readable ID. Keep it unchanged after deployment. |
| `name` | The human-readable name shown in the Android Wisp list. |
| `description` | A short explanation of the Wisp. |
| `state` and `action` | The callbacks WispGate uses to read and update the program. |

## 3. Send actions from the HTML interface

The Android host injects a JavaScript object named `WispGate` into the rendered page. Calling `WispGate.submit(...)` sends one action back to the Python callback.

The simplest form sends a JavaScript object. The injected helper converts it to JSON:

```html
<button onclick='WispGate.submit({type: "increment"})'>Add one</button>
```

Python receives a dictionary whose `type` is `"increment"`:

```python
if payload.get("type") == "increment":
    self.count += 1
```

For several values, pass a larger object. Calling `JSON.stringify(...)` yourself also works, but is not required:

```html
<form onsubmit='event.preventDefault(); WispGate.submit({
  type: "save_name",
  name: this.personName.value
})'>
  <input name="personName">
  <button type="submit">Save</button>
</form>
```

Python can read the values by name:

```python
def action(self, payload: dict) -> dict[str, str]:
    if payload.get("type") == "save_name":
        self.name = str(payload.get("name", "")).strip()
    return self.render()
```

What this step does: it turns ordinary browser events into application-defined Python dictionaries. The Android client does not need to know what `increment` or `save_name` means.

## 4. Return a complete interface after every action

WispGate uses a turn-based model. Python returns a complete UI, Android displays it, and that UI stays unchanged until Python returns another response.

This means `action(...)` should normally finish by returning the complete next screen:

```python
def action(self, payload: dict) -> dict[str, str]:
    self.apply_action(payload)
    return self.render()
```

Do not return only the changed label or assume Android will reconstruct Python state. Returning complete HTML keeps the native client generic and makes the behavior easy to reason about.

What this step does: it makes Python the source of truth. The WebView renders the result but does not independently own the application's lasting state.

## 5. Create the relay configuration

`appserve.load(...)` reads a JSON configuration file. A safe template is:

```json
{
  "server": "YOUR_RELAY_HOST",
  "control_port": 443,
  "relay_port": 4443,
  "bulk_port": 4444,
  "server_public_key": "YOUR_PINNED_BASE64URL_RELAY_PUBLIC_KEY",
  "deployment_id": "private",
  "client_id": "counter-program"
}
```

Use the real values supplied by your private WispGate relay deployment. Do not commit the completed file if it contains private deployment information.

The important fields are:

| Field | Meaning |
|---|---|
| `server` | Relay hostname or address. |
| `control_port` | Port used to authenticate and register the Wisp. |
| `relay_port` | Port used for encrypted interactive messages. |
| `bulk_port` | Port used for encrypted file data. |
| `server_public_key` | Pinned relay bootstrap public key, encoded as base64url DER. |
| `deployment_id` | Identifies the private relay deployment. |
| `client_id` | Identifies this Python endpoint. It is also the Wisp's routing owner. |

On its first launch, the Python module creates a persistent endpoint identity beside this file. It also creates a peer-key store there so it can remember and reject unexpected changes to the Android endpoint key.

What this step does: it tells the reusable runtime where the relay is and which relay identity it is allowed to trust. It does not put application plaintext on the relay.

## 6. Register the Wisp and start serving it

Create a small launcher that joins your existing program to WispGate:

```python
from __future__ import annotations

import asyncio
from pathlib import Path

import appserve

from counter_program import CounterProgram


def main() -> None:
    program = CounterProgram()

    runtime = appserve.load(Path("serverinfo.txt"))
    runtime.register(program.as_wisp())

    try:
        asyncio.run(runtime.serve())
    except KeyboardInterrupt:
        print("Counter Wisp stopped.")


if __name__ == "__main__":
    main()
```

Start it with:

```bash
python run_counter.py
```

What each launcher line does:

1. `CounterProgram()` creates the application and its initial state.
2. `appserve.load(...)` loads relay settings and the persistent endpoint identity.
3. `runtime.register(...)` adds the Wisp's ID, name, description, and callbacks to the catalog registration.
4. `runtime.serve()` connects, registers the Wisp, and waits for encrypted state requests and actions.
5. The `KeyboardInterrupt` handler lets Ctrl+C stop the launcher cleanly.

`serve()` automatically reconnects with exponential backoff if the relay is unavailable or restarts. Your program does not need to write its own reconnect loop.

## 7. Add WispGate to an already-running asynchronous program

If your application already has an `asyncio` event loop, do not call `asyncio.run()` inside it. Start the WispGate server as a task:

```python
import asyncio
import appserve


async def run_program() -> None:
    program = CounterProgram()
    runtime = appserve.load("serverinfo.txt")
    runtime.register(program.as_wisp())

    wispgate_task = asyncio.create_task(runtime.serve())
    try:
        await run_the_rest_of_your_program()
    finally:
        wispgate_task.cancel()
        await asyncio.gather(wispgate_task, return_exceptions=True)
        await runtime.close()


asyncio.run(run_program())
```

What this step does: it lets WispGate share the program's existing event loop instead of becoming a separate application or blocking the rest of the program.

## 8. Use asynchronous action handlers when work must be awaited

An action callback may be a normal function or an `async` function. Use `async` when the action must await a database, another service, or other asynchronous work:

```python
async def action(self, payload: dict) -> dict[str, str]:
    if payload.get("type") == "refresh":
        self.records = await load_records()
    return self.render()
```

The WispGate runtime detects the coroutine and waits for it before returning the next interface.

For slow operations, consider immediately returning a useful status in your application design rather than leaving the user with no feedback. The current turn does not complete until the callback returns.

## 9. Accept files from the interface

For file input, use an ordinary HTML form and the host's `submitForm` helper:

```html
<form id="upload-form">
  <input name="caption">
  <input name="attachments" type="file" multiple>
  <button type="submit">Upload</button>
</form>
<script>
  const form = document.getElementById("upload-form");
  form.addEventListener("submit", event => {
    event.preventDefault();
    WispGate.submitForm(form, {type: "upload"});
  });
</script>
```

The callback receives a dictionary-compatible `WispAction`. Ordinary form fields remain in the dictionary, while uploaded files are under `action.files`:

```python
from pathlib import Path
from appserve import WispAction


def action(self, action: WispAction) -> dict[str, str]:
    if action.get("type") == "upload":
        attachments = action.files.get("attachments", ())
        if not isinstance(attachments, tuple):
            attachments = (attachments,)

        for uploaded in attachments:
            uploaded.save(Path("saved-files") / uploaded.name)

    return self.render()
```

Uploaded temporary files are deleted after the callback returns. Call `uploaded.save(...)` inside the callback if the program must retain one.

What this step does: Android stages the browser-selected file, sends its metadata through the encrypted peer session, and sends opaque encrypted file bytes through the relay's bulk connection. The relay does not receive the plaintext contents or private file metadata.

## 10. Return images or larger files to Android

Do not place a large file in the HTML as base64 or a `data:` URL. Describe it with `WispAsset`, return it with `WispResponse`, and reference its local WispGate URL from the HTML:

```python
from appserve import WispAsset, WispResponse


def render_image(png: bytes) -> WispResponse:
    return WispResponse(
        html="""
          <main>
            <img
              src="https://wisp.local/_wispgate/assets/result-image"
              alt="Generated result"
            >
            <button onclick='WispGate.submit({type: "make_another"})'>
              Make another
            </button>
          </main>
        """,
        assets=(
            WispAsset.from_bytes(
                id="result-image",
                name="result.png",
                content_type="image/png",
                data=png,
            ),
        ),
    )
```

For a file already stored on disk, avoid loading it all into Python memory:

```python
asset = WispAsset.from_path(
    id="report",
    path="generated/report.pdf",
    content_type="application/pdf",
)
```

The asset ID is a URL-safe identifier containing letters, digits, `.`, `_`, `~`, or `-`. It must match the final segment in `https://wisp.local/_wispgate/assets/<asset-id>`.

What this step does: WispGate sends the small HTML and encrypted asset manifest through the peer session, streams the authenticated file ciphertext through the opaque bulk relay, verifies it on Android, and exposes only that response's declared assets to the WebView. Android deletes the private cached files when that Wisp response is replaced or closed. One response may contain up to 32 assets totaling at most 256 MiB.

The complete QR example is in `examples/qr_wisp.py`; launch it with `python examples/run_qr.py` after installing `python -m pip install -r examples/requirements.txt`.

## 11. Use the host theme or provide your own

By default, Android injects local CSS matching the device's light or dark mode. A simple Wisp can therefore provide semantic HTML without duplicating the host theme.

If the Wisp supplies its entire visual design, opt out by including this element:

```html
<meta name="wispgate-theme" content="custom">
```

What this step does: it changes presentation only. It does not affect state, actions, encryption, or routing.

## 12. Register more than one Wisp from one program

One Python endpoint may expose several Wisps:

```python
runtime = appserve.load("serverinfo.txt")
runtime.register(CounterProgram().as_wisp())
runtime.register(StatusDashboard().as_wisp())
runtime.register(AdminTools().as_wisp())
await runtime.serve()
```

Give every Wisp a unique `id`. They share one Python endpoint connection and endpoint identity, but each Wisp keeps its own UI and behavior.

## 13. Test the program boundary

Test `state()` and `action(...)` without connecting to the relay first:

```python
def test_counter_state_request_does_not_change_count() -> None:
    program = CounterProgram()

    first = program.state()
    second = program.state()

    assert program.count == 0
    assert first == second


def test_counter_action_updates_the_next_interface() -> None:
    program = CounterProgram()

    response = program.action({"type": "increment"})

    assert program.count == 1
    assert "Count: 1" in response["html"]
```

The most important behavior to preserve is:

- opening or refreshing a Wisp calls `state()` and does not advance it;
- a user event calls `action(...)` once;
- the action returns the complete next UI;
- app-specific logic remains in Python, not in Android or the relay.

After focused tests, verify one real vertical interaction:

1. Start the relay.
2. Start the Python launcher.
3. Confirm the Wisp appears in Android.
4. Open it and confirm the initial HTML renders.
5. Perform one action.
6. Confirm Python changes state and Android renders the returned HTML.

## Common mistakes

### Changing state inside `state()`

Opening a Wisp is a read operation. If `state()` advances a game turn, consumes a queue item, or modifies a counter, merely opening or refreshing the Wisp changes the program unexpectedly.

### Returning only part of the screen

The current runtime expects each response to describe the complete next interface. Return the whole HTML view after every action.

### Putting app-specific controls in Android

Do not add a native `Counter` button or special `Prime` screen. Put those controls in the Wisp's HTML. Android should remain a generic Wisp host.

### Calling `asyncio.run()` from an existing event loop

Use `asyncio.create_task(runtime.serve())` when your application is already asynchronous.

### Forgetting to retain uploaded files

Temporary uploads disappear after the action callback. Save files inside the callback if they must persist.

### Treating relay acceptance as completed processing

A relay acknowledgement means only that a frame was accepted for forwarding. The next complete Wisp response proves that the Python callback processed the action.

### Committing deployment configuration or identity files

Keep completed relay configuration, generated private identity files, and peer trust stores out of source control.

## Minimal implementation checklist

- [ ] Import `appserve`.
- [ ] Keep your program's state in an ordinary Python object.
- [ ] Implement a non-mutating `state()` method.
- [ ] Implement `action(payload)` and return the complete next UI.
- [ ] Wrap the callbacks in a `Wisp` with a stable ID and readable name.
- [ ] Create a private `serverinfo.txt` from your relay values.
- [ ] Load the runtime and register the Wisp.
- [ ] Start `runtime.serve()` in the program's event loop.
- [ ] Use `WispResponse` and `WispAsset` instead of embedding large bytes in HTML.
- [ ] Test `state()` and `action(...)` directly.
- [ ] Verify one real open-and-action round trip in Android.

## Existing working example

The repository's smallest working reference is:

- `examples/prime_wisp.py` — application state, HTML, and action handling;
- `examples/run_prime.py` — configuration loading, registration, and serving;
- `examples/qr_wisp.py` — Wisp-to-Android image assets rendered inline;
- `examples/run_qr.py` — QR example launcher.

Use those files as the local pattern when adding another Wisp.