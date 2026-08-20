"""Run the transcription/diarization Wisp against the configured relay."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path


LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import appserve
from examples.transcription_wisp import TranscriptionWisp


def find_serverinfo(cwd: Path | None = None) -> Path:
    launch_directory = cwd or Path.cwd()
    candidate = launch_directory / "serverinfo.txt"
    return candidate if candidate.exists() else Path(__file__).with_name("serverinfo.txt")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the transcription/diarization Wisp")
    parser.add_argument("--debug", action="store_true", help="log relay, session, and transfer activity")
    parser.add_argument("--reset-peer-trust", action="store_true", help="forget the stored Android peer key once")
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format=LOG_FORMAT,
    )
    runtime = appserve.load(find_serverinfo(), reset_peer_trust=args.reset_peer_trust)
    runtime.register(TranscriptionWisp().as_wisp())
    try:
        asyncio.run(runtime.serve())
    except KeyboardInterrupt:
        print("Transcription Wisp stopped.")


if __name__ == "__main__":
    main()
