# Catalog and liveness

Wisp manifests are durable registration metadata. Endpoint liveness is transient relay state.

- A control registration persists the Wisp manifest.
- An offline owner is omitted from client catalogs.
- A relay connection adds the endpoint to live sessions and immediately broadcasts `catalog_update` to registered control clients.
- A relay disconnect removes only live session/liveness state; durable manifests remain.
- A reconnect broadcasts the catalog again.

`catalog_update` is:

```json
{"ok":true,"type":"catalog_update","items":[{"id":"...","owner":"<endpoint uuid>","public_key":"..."}]}
```
