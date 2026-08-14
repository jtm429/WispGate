#!/usr/bin/env bash
set -euo pipefail

repo=/opt/wispgate

sudo -n -u wisp -- git -C "$repo" fetch origin main
sudo -n -u wisp -- git -C "$repo" merge --ff-only origin/main
systemctl restart wispgate-relay.service
