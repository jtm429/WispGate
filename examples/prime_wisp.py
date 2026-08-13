"""A minimal Wisp: centered number input and prime-result response."""

from __future__ import annotations

import html

from appserve import Wisp


class PrimeWisp:
    def __init__(self):
        self.current = self.render("")

    @staticmethod
    def is_prime(value: int) -> bool:
        if value < 2:
            return False
        if value % 2 == 0:
            return value == 2
        divisor = 3
        while divisor * divisor <= value:
            if value % divisor == 0:
                return False
            divisor += 2
        return True

    @staticmethod
    def render(result: str) -> dict[str, str]:
        message = html.escape(result)
        return {
            "content_type": "text/html",
            "html": f"""
            <main style='min-height:100vh;display:flex;align-items:center;justify-content:center'>
              <form id='prime-form' onsubmit='event.preventDefault(); window.WispGate.submit(JSON.stringify({{type:"submit", number:this.number.value}}))' style='display:flex;flex-direction:column;gap:12px;align-items:center'>
                <input name='number' type='number' placeholder='Enter a number' autofocus />
                <button type='submit'>Is it prime?</button>
                <output>{message}</output>
              </form>
            </main>
            """.strip(),
        }

    def state(self) -> dict[str, str]:
        return self.current

    def action(self, action: dict[str, str]) -> dict[str, str]:
        if action.get("type") == "submit":
            raw = action.get("number", "")
            try:
                number = int(raw)
                result = f"{number} is {'prime' if self.is_prime(number) else 'not prime'}."
            except ValueError:
                result = "Please enter a whole number."
            self.current = self.render(result)
        return self.current

    def as_wisp(self) -> Wisp:
        return Wisp("prime", "Prime tester", "Tests whether a number is prime", self.state, self.action)
