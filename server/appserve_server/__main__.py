"""Command-line entry point for the appserve relay."""

from __future__ import annotations

import argparse
import asyncio
import logging
import subprocess
from pathlib import Path

from .core import RelayConfig, RelayState
from .service import RelayRuntime, serve


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--private-key", type=Path, required=True)
    result.add_argument("--tls-cert", type=Path, required=True)
    result.add_argument("--tls-key", type=Path, required=True)
    result.add_argument("--state", type=Path, required=True)
    result.add_argument("--deployment-id", default="private")
    result.add_argument("--allow-enrollment", action="store_true")
    result.add_argument("--control-host", default="0.0.0.0")
    result.add_argument("--control-port", type=int, default=443)
    result.add_argument("--relay-host", default="0.0.0.0")
    result.add_argument("--relay-port", type=int, default=4443)
    result.add_argument("--bulk-host", default="0.0.0.0")
    result.add_argument("--bulk-port", type=int, default=4444)
    result.add_argument("--log-level", default="INFO")
    result.add_argument("--update-script", type=Path)
    return result


def main() -> None:
    args = parser().parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level.upper()), format="%(asctime)s %(levelname)s %(name)s %(message)s")
    key = args.private_key.read_bytes()
    state = RelayState(args.state)
    state.load()
    update_command = ("/usr/bin/sudo", "-n", str(args.update_script)) if args.update_script else None
    try:
        server_version = subprocess.check_output(
            ("git", "rev-parse", "--short", "HEAD"),
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        server_version = "unknown"
    runtime = RelayRuntime(
        RelayConfig(
            key,
            deployment_id=args.deployment_id,
            enrollment_enabled=args.allow_enrollment,
        ),
        state,
        update_command=update_command,
        server_version=server_version,
    )
    asyncio.run(serve(
        runtime,
        args.control_host,
        args.control_port,
        args.relay_host,
        args.relay_port,
        args.bulk_host,
        args.bulk_port,
        tls_cert_path=args.tls_cert,
        tls_key_path=args.tls_key,
    ))


if __name__ == "__main__":
    main()
