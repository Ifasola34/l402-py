"""Client-side: parse_challenge_header, make_auth_header, L402Client."""

import io
import urllib.error
from unittest.mock import MagicMock, patch

import pytest

from l402.backends import DeterministicMockBackend
from l402.client import (
    L402Client,
    ParsedChallenge,
    make_auth_header,
    parse_challenge_header,
)
from l402.server import authorize, make_challenge


SECRET = b"client-test-secret-32-bytes-pads"


# ---------- parse_challenge_header --------------------------------


def test_parse_quoted_values():
    h = 'L402 macaroon="AAAA", invoice="lnbc1pmocked"'
    p = parse_challenge_header(h)
    assert p.macaroon_token == "AAAA"
    assert p.invoice_bolt11 == "lnbc1pmocked"


def test_parse_param_order_irrelevant():
    h = 'L402 invoice="lnbc1z", macaroon="MAC"'
    p = parse_challenge_header(h)
    assert p.macaroon_token == "MAC"
    assert p.invoice_bolt11 == "lnbc1z"


def test_parse_case_insensitive_scheme():
    h = 'l402 macaroon="x", invoice="y"'
    p = parse_challenge_header(h)
    assert p.macaroon_token == "x"


def test_parse_tolerates_extra_whitespace():
    h = '  L402   macaroon = "MAC"  ,  invoice = "lnbc1z"  '
    p = parse_challenge_header(h)
    assert p.macaroon_token == "MAC"


def test_parse_rejects_non_l402():
    with pytest.raises(ValueError, match="not an L402"):
        parse_challenge_header('Bearer abcdef')


def test_parse_rejects_missing_invoice():
    with pytest.raises(ValueError, match="missing"):
        parse_challenge_header('L402 macaroon="x"')


def test_parse_rejects_missing_macaroon():
    with pytest.raises(ValueError, match="missing"):
        parse_challenge_header('L402 invoice="lnbc"')


# ---------- make_auth_header --------------------------------------


def test_make_auth_header_simple():
    assert make_auth_header("MAC", "ab" * 32) == f"L402 MAC:{'ab' * 32}"


def test_make_auth_header_rejects_colon_in_token():
    with pytest.raises(ValueError, match="contains ':'"):
        make_auth_header("MAC:has:colons", "ab" * 32)


# ---------- L402Client end-to-end ---------------------------------


class _FakeHTTPError(urllib.error.HTTPError):
    """An HTTPError carrying real headers + body so the client's
    _one_call path treats it like a non-200 response."""
    def __init__(self, code, body_bytes, headers):
        super().__init__(
            url="http://test/", code=code, msg="status", hdrs=headers,
            fp=io.BytesIO(body_bytes),
        )
        self._body = body_bytes

    def read(self):
        return self._body


def test_client_handles_402_then_retries_with_auth():
    """Full dance: GET → 402 with challenge → pay → retry → 200."""
    ln = DeterministicMockBackend()
    chal = make_challenge(SECRET, ln, resource_id="api:premium")
    www_auth = chal.header_value()

    # First call: HTTPError 402 with WWW-Authenticate.
    # Second call: 200 OK with body.
    headers_402 = {"WWW-Authenticate": www_auth}
    second_resp = MagicMock()
    second_resp.status = 200
    second_resp.read.return_value = b'{"premium": true}'
    second_resp.headers.get.return_value = None
    second_resp.__enter__ = lambda self: self
    second_resp.__exit__ = lambda *a: None

    call_count = {"n": 0}
    captured_headers = {}

    def fake_urlopen(req, timeout=None):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise _FakeHTTPError(402, b"", headers_402)
        # Capture what the retry sent.
        captured_headers["Authorization"] = req.headers.get("Authorization")
        return second_resp

    def pay_callback(challenge: ParsedChallenge) -> str:
        # Real client would pay the invoice externally; we use the
        # mock's reveal mechanism.
        return ln.reveal_preimage(chal.payment_hash)

    client = L402Client(pay_callback=pay_callback)
    with patch("l402.client.urllib.request.urlopen", side_effect=fake_urlopen):
        status, body = client.get("http://test/api/premium")

    assert status == 200
    assert body == b'{"premium": true}'
    # Verify the retry actually presented the correct Authorization.
    assert captured_headers["Authorization"].startswith("L402 ")
    parsed = parse_challenge_header(www_auth)
    assert parsed.macaroon_token in captured_headers["Authorization"]


def test_client_returns_402_when_max_retries_exhausted():
    """If retry doesn't satisfy the server, we don't infinite-loop."""
    headers_402 = {"WWW-Authenticate": 'L402 macaroon="m", invoice="lnbc"'}

    def always_402(req, timeout=None):
        raise _FakeHTTPError(402, b"still no", headers_402)

    def pay_cb(challenge: ParsedChallenge) -> str:
        return "00" * 32

    client = L402Client(pay_callback=pay_cb, max_retries=1)
    with patch("l402.client.urllib.request.urlopen", side_effect=always_402):
        status, body = client.get("http://test/")
    assert status == 402
    assert body == b"still no"


def test_client_propagates_non_402_errors():
    """A 500 from the server should NOT trigger the pay flow."""
    def server_error(req, timeout=None):
        raise _FakeHTTPError(500, b"explosion", {})

    pay_calls = {"n": 0}

    def pay_cb(c):
        pay_calls["n"] += 1
        return "00" * 32

    client = L402Client(pay_callback=pay_cb)
    with patch("l402.client.urllib.request.urlopen", side_effect=server_error):
        status, body = client.get("http://test/")
    assert status == 500
    assert pay_calls["n"] == 0, "must not invoke pay_callback on 500"
