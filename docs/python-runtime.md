# Python runtime contract

`appserve` owns endpoint transport, session crypto, relay acknowledgements, operation lifecycle, encrypted file transfer, response assets, and callback execution.

Wisp callbacks receive application data and a trusted `WispContext(peer_id=...)`. The peer ID is derived from the authenticated session sender. Legacy callback signatures are temporarily supported for migration.
