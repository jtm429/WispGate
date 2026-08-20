from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "examples" / "run_transcription.py"


def test_transcription_launcher_exposes_debug_flag() -> None:
    result = subprocess.run(
        [sys.executable, str(LAUNCHER), "--help"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    assert "--debug" in result.stdout
    assert "--reset-peer-trust" in result.stdout
    assert "relay, session, and transfer activity" in result.stdout
