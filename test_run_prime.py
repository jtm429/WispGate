import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))

from run_prime import find_serverinfo


def test_find_serverinfo_prefers_launch_directory(tmp_path):
    expected = tmp_path / "serverinfo.txt"
    expected.write_text("{}", encoding="utf-8")
    assert find_serverinfo(tmp_path) == expected
