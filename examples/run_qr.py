"""Run the example QR-code Wisp against the configured relay."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

import appserve
from examples.qr_wisp import QrWisp


def find_serverinfo(cwd: Path | None = None) -> Path:
    launch_directory = cwd or Path.cwd()
    serverinfo = launch_directory / "serverinfo.txt"
    if serverinfo.exists():
        return serverinfo
    return Path(__file__).with_name("serverinfo.txt")


def main() -> None:
    runtime = appserve.load(find_serverinfo())
    runtime.register(QrWisp().as_wisp())
    try:
        asyncio.run(runtime.serve())
    except KeyboardInterrupt:
        print("QR-code Wisp stopped.")


if __name__ == "__main__":
    main()
