from __future__ import annotations

from appserve import WispContext, WispResponse
from examples.qr_wisp import QrWisp


def test_qr_wisp_turns_link_into_static_inline_png_then_resets() -> None:
    program = QrWisp()

    context = WispContext("test-peer")
    initial = program.state(context)
    generated = program.action({"type": "make_qr", "link": "https://example.com/path"}, context)

    assert isinstance(initial, dict)
    assert "name=\"link\"" in initial["html"]
    assert isinstance(generated, WispResponse)
    assert len(generated.assets) == 1
    qr = generated.assets[0]
    assert qr.id == "qr-code"
    assert qr.content_type == "image/png"
    assert qr.open().read(8) == b"\x89PNG\r\n\x1a\n"
    assert '<img src="https://wisp.local/_wispgate/assets/qr-code"' in generated.html
    assert "download" not in generated.html.lower()
    assert "Make another QR code" in generated.html

    reset = program.action({"type": "make_another"}, context)

    assert isinstance(reset, dict)
    assert "name=\"link\"" in reset["html"]


def test_qr_wisp_reports_an_overlong_link_instead_of_crashing() -> None:
    program = QrWisp()

    response = program.action({"type": "make_qr", "link": "https://example.com/" + "x" * 5000}, WispContext("test-peer"))

    assert isinstance(response, dict)
    assert "Link must be 2,048 characters or fewer." in response["html"]


def test_qr_wisp_reports_data_that_does_not_fit_a_qr_code() -> None:
    program = QrWisp()

    response = program.action({"type": "make_qr", "link": "https://example.com/" + "😀" * 2000}, WispContext("test-peer"))

    assert isinstance(response, dict)
    assert "This link contains too much data for a QR code." in response["html"]
