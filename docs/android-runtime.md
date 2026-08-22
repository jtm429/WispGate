# Android runtime contract

The Android runtime owns endpoint identity, RSA bootstrap/session handshakes, UUID routing identities, explicit AES direction, relay acknowledgements, catalog updates, operation IDs, and bulk assets.

Android endpoint UUID is used unchanged in every sender/recipient field. Session role is explicit (`androidSide=true`), never inferred from a logical alias.
