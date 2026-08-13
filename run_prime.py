"""Run the example Prime Wisp against the configured relay."""

from __future__ import annotations

import asyncio
from pathlib import Path

import appserve
from examples.prime_wisp import PrimeWisp


def find_serverinfo(cwd: Path | None = None) -> Path:
    """Find serverinfo.txt in the launch directory, then beside this file."""
    launch_directory = cwd or Path.cwd()
    serverinfo = launch_directory / "serverinfo.txt"
    if serverinfo.exists():
        return serverinfo
    return Path(__file__).with_name("serverinfo.txt")


def main() -> None:
    """Load serverinfo.txt, register the Prime Wisp, and serve it."""
    runtime = appserve.load(find_serverinfo())
    runtime.register(PrimeWisp().as_wisp())
    asyncio.run(runtime.serve())


if __name__ == "__main__":
    main()
