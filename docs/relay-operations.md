# Relay operations

Deploy relay first, then Android, then Python Wisp runtimes. Verify:

1. endpoint authentication;
2. Wisp registration persistence;
3. relay connect catalog broadcast;
4. one state request;
5. one operation and reconnect/resume;
6. one uploaded file and response asset;
7. relay disconnect/reconnect liveness.

Inspect `broadcasting catalog_update` logs and confirm the control client is present in `control_clients`.
