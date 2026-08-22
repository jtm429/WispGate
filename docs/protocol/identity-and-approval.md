# Identity and approval

Every endpoint has:

- a persistent UUID;
- a 3072-bit RSA identity key;
- an approved/pending/rejected lifecycle in durable relay state.

Endpoint UUIDs are used unchanged as RSA envelope `sender`/`recipient`, AES session-envelope identities, proof transcript identities, and relay routing keys. There is no `android-user` alias or sender translation table.

New endpoints remain pending until an explicit administrator claim action approves them.
