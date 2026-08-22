# Response assets

A Wisp returns `WispResponse` with zero or more `WispAsset` values. The runtime sends the response metadata, transfers each encrypted asset through the bulk lane, and sends completion metadata. Asset IDs, sizes, content types, ownership, and transfer tickets are validated by the runtime. Temporary files are cleaned after completion or failure.

Applications return assets; they do not manage relay bulk sockets or encryption.
