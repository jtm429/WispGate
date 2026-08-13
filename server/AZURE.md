# Azure relay deployment

The relay is designed for a small Azure Linux VM that can be stopped when not in use. Starting the VM starts the relay automatically through `systemd`.

## 1. Create the VM

In the Azure portal:

1. Create an Ubuntu 24.04 LTS Linux VM.
2. Use SSH public-key authentication.
3. Give it a static public IP or a stable DNS name.
4. Do not enable password login.
5. Create inbound network-security-group rules for TCP `443` and `4443`, restricted to the source IP ranges you actually need. Keep SSH (`22`) restricted to your own IP.
6. Record the public DNS name or IP.

The relay clients initiate outbound connections; only the Azure VM needs public inbound ports.

## 2. Install system packages

SSH into the VM:

```bash
sudo apt update
sudo apt install -y git python3 python3-venv openssl
sudo useradd --system --home /opt/wispgate --shell /usr/sbin/nologin wisp || true
sudo mkdir -p /opt/wispgate /var/lib/wispgate
sudo chown -R wisp:wisp /opt/wispgate /var/lib/wispgate
```

## 3. Install the server

```bash
sudo -u wisp git clone https://github.com/jtm429/WispGate.git /opt/wispgate
sudo -u wisp python3 -m venv /opt/wispgate/.venv
sudo -u wisp /opt/wispgate/.venv/bin/pip install --upgrade pip
sudo -u wisp /opt/wispgate/.venv/bin/pip install -r /opt/wispgate/server/requirements.txt
```

## 4. Generate the server key

The private key must persist across VM shutdowns. Do not regenerate it during each boot.

```bash
sudo -u wisp bash -c 'cd /opt/wispgate/server && /opt/wispgate/.venv/bin/python -c "from pathlib import Path; from appserve_server.core import generate_server_keypair; print(generate_server_keypair(Path(\"/var/lib/wispgate/server-key.pem\")))"'
sudo chmod 600 /var/lib/wispgate/server-key.pem
```

The command prints the base64url server public key. Put that value in each private client's `serverinfo.txt`. Treat the key as a pinned deployment bootstrap value.

## 5. Install the boot service

```bash
sudo cp /opt/wispgate/server/wispgate-relay.service /etc/systemd/system/wispgate-relay.service
sudo systemctl daemon-reload
sudo systemctl enable wispgate-relay
sudo systemctl start wispgate-relay
sudo systemctl status wispgate-relay
```

`enable` is important: it makes the relay start immediately whenever the Azure VM boots. `Restart=always` restarts it if the process exits.

View logs:

```bash
sudo journalctl -u wispgate-relay -f
```

## 6. Verify readiness

From the VM:

```bash
sudo ss -ltnp | grep -E ':443|:4443'
sudo systemctl is-active wispgate-relay
```

The service is ready when both ports are listening and `systemctl is-active` prints `active`.

## 7. Stopping and starting to save money

Stop the relay cleanly before deallocating the VM:

```bash
sudo systemctl stop wispgate-relay
```

Then stop/deallocate the VM from Azure. When it is started again, systemd starts WispGate without an interactive login:

```text
Azure VM boot -> systemd -> WispGate relay -> clients reconnect
```

The relay state file and private key are in `/var/lib/wispgate`, so they survive normal VM shutdowns. Do not delete the resource disk or recreate the VM without backing up that directory.

## Current MVP limitations

- The current service uses newline-delimited JSON over two asyncio TCP ports.
- The bootstrap payload is encrypted to the relay RSA public key.
- The application envelope's `ciphertext` is treated as opaque, but this MVP does not yet implement client-side end-to-end session-key negotiation.
- The sockets are currently plaintext TCP. Before public deployment, add TLS termination in front of both ports or wire `ssl.SSLContext` into `asyncio.start_server`.
- The relay startup reconnect behavior is represented in the protocol design, but direct relay-initiated NAT reconnection requires a future transport implementation. Clients' reconnect loops work with this MVP.

Do not expose the current MVP directly to the public internet until TLS and the remaining client authentication/session work are implemented.
