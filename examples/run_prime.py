"""Run the example Prime Wisp against the configured relay."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

# Allow direct execution as ``python run_prime.py`` from this directory.
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

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
    try:
        asyncio.run(runtime.serve())
    except KeyboardInterrupt:
        print("Prime Wisp stopped.")


if __name__ == "__main__":
    main()
