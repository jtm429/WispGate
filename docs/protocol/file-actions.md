# File actions

The Android runtime describes uploaded files with bounded manifests and transfers encrypted content through the relay bulk lane. The Python runtime validates counts, names, IDs, sizes, ownership, and ciphertext metadata before exposing `UploadedFile` objects to the Wisp callback.

Wisps receive uploaded files through `WispAction.files`; they do not implement TLS, bulk pairing, encryption, cleanup, or relay acknowledgements.
