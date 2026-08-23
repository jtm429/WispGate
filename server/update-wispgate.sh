#!/usr/bin/env bash
set -euo pipefail

repo=/opt/wispgate
log=/var/lib/wispgate/update.log

# The updater is launched from the relay service itself. Keep diagnostics after
# the service is restarted, and do not synchronously wait for our parent unit
# to stop while we are still running inside its cgroup.
exec >>"$log" 2>&1
printf '\n[%s] WispGate update requested\n' "$(date --iso-8601=seconds)"

sudo -n -u wisp -- git -C "$repo" fetch origin main
sudo -n -u wisp -- git -C "$repo" merge --ff-only origin/main
printf '[%s] checked_out=%s\n' "$(date --iso-8601=seconds)" "$(git -C "$repo" rev-parse --short HEAD)"
systemctl restart --no-block wispgate-relay.service
printf '[%s] restart_queued\n' "$(date --iso-8601=seconds)"
