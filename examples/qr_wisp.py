"""Example Wisp that turns an HTTP(S) link into an inline QR-code image."""

from __future__ import annotations

import html
import io
from urllib.parse import urlparse

import qrcode

from appserve import Wisp, WispAsset, WispResponse


class QrWisp:
    def __init__(self) -> None:
        self.current: WispResponse | dict[str, str] = self._form()

    @staticmethod
    def _form(message: str = "") -> dict[str, str]:
        notice = f"<p role='alert'>{html.escape(message)}</p>" if message else ""
        return {
            "content_type": "text/html",
            "html": f"""
            <main style="min-height:100vh;display:flex;align-items:center;justify-content:center">
              <form onsubmit='event.preventDefault(); WispGate.submit({{type:"make_qr", link:this.link.value}})' style="display:flex;flex-direction:column;gap:12px;width:min(90vw,32rem)">
                <label for="link">Link</label>
                <input id="link" name="link" type="url" inputmode="url" maxlength="2048" placeholder="https://example.com" required autofocus>
                <button type="submit">Make QR code</button>
                {notice}
              </form>
            </main>
            """.strip(),
        }

    @staticmethod
    def _make_png(link: str) -> bytes:
        image = qrcode.make(link)
        output = io.BytesIO()
        image.save(output, format="PNG")
        return output.getvalue()

    @staticmethod
    def _result(png: bytes) -> WispResponse:
        return WispResponse(
            html="""
            <main style="min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:18px">
              <img src="https://wisp.local/_wispgate/assets/qr-code" alt="Generated QR code" style="width:min(82vw,32rem);height:auto;image-rendering:pixelated">
              <button type="button" onclick='WispGate.submit({type:"make_another"})'>Make another QR code</button>
            </main>
            """.strip(),
            assets=(WispAsset.from_bytes("qr-code", "qr.png", "image/png", png),),
        )

    def state(self) -> WispResponse | dict[str, str]:
        return self.current

    def action(self, action: dict[str, str]) -> WispResponse | dict[str, str]:
        action_type = action.get("type")
        if action_type == "make_another":
            self.current = self._form()
        elif action_type == "make_qr":
            link = str(action.get("link", "")).strip()
            parsed = urlparse(link)
            if len(link) > 2048:
                self.current = self._form("Link must be 2,048 characters or fewer.")
            elif parsed.scheme not in {"http", "https"} or not parsed.netloc:
                self.current = self._form("Enter a complete http:// or https:// link.")
            else:
                try:
                    self.current = self._result(self._make_png(link))
                except ValueError:
                    self.current = self._form("This link contains too much data for a QR code.")
        return self.current

    def as_wisp(self) -> Wisp:
        return Wisp(
            "qr-code",
            "QR code maker",
            "Turns a link into a static QR-code image",
            self.state,
            self.action,
        )
