"""Command-line entry point for the appserve relay."""

from __future__ import annotations

import argparse
import asyncio
import logging
from pathlib import Path

from .core import RelayConfig, RelayState
from .service import RelayRuntime, serve


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--private-key", type=Path, required=True)
    result.add_argument("--state", type=Path, required=True)
    result.add_argument("--deployment-id", default="private")
    result.add_argument("--control-host", default="0.0.0.0")
    result.add_argument("--control-port", type=int, default=443)
    result.add_argument("--relay-host", default="0.0.0.0")
    result.add_argument("--relay-port", type=int, default=4443)
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
    runtime = RelayRuntime(
        RelayConfig(key, deployment_id=args.deployment_id),
        state,
        update_command=update_command,
    )
    asyncio.run(serve(runtime, args.control_host, args.control_port, args.relay_host, args.relay_port))


if __name__ == "__main__":
    main()
