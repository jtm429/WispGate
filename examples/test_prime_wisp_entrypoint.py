import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_prime_wisp_can_be_run_directly_from_examples_directory():
    result = subprocess.run(
        [sys.executable, "prime_wisp.py"],
        cwd=ROOT / "examples",
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": ""},
    )
    assert result.returncode == 0, result.stderr
    assert "ModuleNotFoundError" not in result.stderr
