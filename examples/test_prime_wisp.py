from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parents[1]))

from examples.prime_wisp import PrimeWisp


def test_prime_wisp_initial_ui_is_centered_form():
    state = PrimeWisp().state()
    assert "justify-content:center" in state["html"]
    assert "type='number'" in state["html"]
    assert "Is it prime?" in state["html"]


def test_prime_wisp_updates_state_after_submit():
    wisp = PrimeWisp()
    result = wisp.action({"type": "submit", "number": "17"})
    assert "17 is prime" in result["html"]

    result = wisp.action({"type": "submit", "number": "21"})
    assert "21 is not prime" in result["html"]
