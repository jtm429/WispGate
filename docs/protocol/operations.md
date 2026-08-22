# Operations

Android generates stable operation IDs for mutating actions. The Python runtime owns running, completed, expired, and indeterminate lifecycle responses and keys retained state by `(authenticated_peer_uuid, operation_id)`.

A reconnect may resume an operation. The runtime must not execute a completed operation twice. Callback exceptions become protocol-level operation results and are logged with traceback details.
