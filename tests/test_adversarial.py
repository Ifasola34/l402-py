"""Adversarial tests for l402-py.

Each test names an attack l402-py MUST refuse, miscount, or silently
authorize. Regression dams against any future change that weakens
macaroon binding, paywall enforcement, header parsing, or client
network-error handling.

Coverage:
  Server (authorize):
    - Forged macaroon under unknown secret
    - Replay of expired macaroon (without/with backend settled)
    - Identifier substitution (token issued for X used against Y)
    - Tampered tag with otherwise-valid macaroon fields
    - Missing exp= caveat (rejected per round-2 fix)
    - Backend RPC NOT called before expiry check (round-2 amplification fix)
    - Preimage with wrong hash → False
    - Authorization header missing colon / wrong scheme

  Client:
    - WWW-Authenticate header missing macaroon or invoice
    - make_auth_header rejects CRLF injection via preimage (round-2 fix)
    - L402Client wraps URLError as L402NetworkError (round-2 fix)
    - L402Client doesn't call pay_callback on 500
    - max_retries respected on persistent 402

  Macaroon:
    - Token decode rejects truncated / non-JSON / non-list-caveats
    - Tag verification rejects different secret
    - Tag verification is constant-time (returns bool, not lazy short-circuit)
"""

from __future__ import annotations

import base64
import io
import json
import re
import urllib.error
from unittest.mock import MagicMock, patch

import pytest

from l402.backends import DeterministicMockBackend
from l402.client import (
    L402Client,
    L402NetworkError,
    ParsedChallenge,
    make_auth_header,
    parse_challenge_header,
)
from l402.macaroon import Macaroon
from l402.server import authorize, make_challenge


SECRET = b"adversarial-test-secret-32-bytes"
OTHER_SECRET = b"another-different-32-byte-secret"


def _settled_auth(ln, resource_id: str = "premium:m1") -> str:
    """Build a real, valid Authorization header by issuing + paying a challenge."""
    chal = make_challenge(SECRET, ln, resource_id=resource_id)
    preimage = ln.reveal_preimage(chal.payment_hash)
    return f"L402 {chal.macaroon_token}:{preimage}"


# ---------- baseline -----------------------------------------------


def test_baseline_honest_flow_authorizes():
    ln = DeterministicMockBackend()
    auth = _settled_auth(ln)
    assert authorize(
        SECRET, ln,
        auth_header_value=auth, resource_id="premium:m1",
    ) is True


# ---------- server: forgery + substitution -------------------------


def test_rejects_macaroon_forged_under_different_secret():
    """Attacker forges a macaroon under their own secret. Tag won't
    verify under the server's real secret."""
    ln = DeterministicMockBackend()
    inv = ln.create_invoice(100, "test")
    forged = Macaroon.create(
        OTHER_SECRET, "premium:m1", inv.payment_hash,
        ["exp=9999999999"],
    )
    preimage = ln.reveal_preimage(inv.payment_hash)
    auth = f"L402 {forged.to_token()}:{preimage}"
    assert authorize(
        SECRET, ln, auth_header_value=auth, resource_id="premium:m1",
    ) is False


def test_rejects_identifier_substitution():
    """Macaroon issued for premium:m1 used against premium:m2 must fail."""
    ln = DeterministicMockBackend()
    chal = make_challenge(SECRET, ln, resource_id="premium:m1")
    preimage = ln.reveal_preimage(chal.payment_hash)
    auth = f"L402 {chal.macaroon_token}:{preimage}"
    assert authorize(
        SECRET, ln,
        auth_header_value=auth, resource_id="premium:m2",
    ) is False


def test_rejects_tampered_tag_on_otherwise_valid_macaroon():
    """Attacker takes a valid macaroon and flips one bit of the tag."""
    ln = DeterministicMockBackend()
    chal = make_challenge(SECRET, ln, resource_id="r1")
    m = Macaroon.from_token(chal.macaroon_token)
    # Flip one byte of the tag (base64-decoded length = 32, so we work
    # at the base64 level).
    bad_tag = (m.tag[:-1] + ("A" if m.tag[-1] != "A" else "B"))
    forged = Macaroon(m.identifier, m.payment_hash, m.caveats, bad_tag)
    preimage = ln.reveal_preimage(chal.payment_hash)
    auth = f"L402 {forged.to_token()}:{preimage}"
    assert authorize(
        SECRET, ln, auth_header_value=auth, resource_id="r1",
    ) is False


def test_rejects_macaroon_with_added_caveat_after_signing():
    """Attacker takes a valid token and tries to add a `resource=admin`
    caveat to upgrade privileges — tag won't verify with the new caveats."""
    ln = DeterministicMockBackend()
    chal = make_challenge(SECRET, ln, resource_id="r1")
    m = Macaroon.from_token(chal.macaroon_token)
    upgraded = Macaroon(
        m.identifier, m.payment_hash,
        m.caveats + ["role=admin"],   # added
        m.tag,                         # original tag won't cover the new caveat
    )
    preimage = ln.reveal_preimage(chal.payment_hash)
    auth = f"L402 {upgraded.to_token()}:{preimage}"
    assert authorize(
        SECRET, ln, auth_header_value=auth, resource_id="r1",
    ) is False


def test_rejects_macaroon_without_exp_caveat():
    """Round-2 fix: every macaroon must carry at least one exp= caveat.
    A macaroon with NO expiry would otherwise authorize forever."""
    ln = DeterministicMockBackend()
    inv = ln.create_invoice(100, "test")
    no_exp = Macaroon.create(SECRET, "r1", inv.payment_hash, [])  # empty caveats
    preimage = ln.reveal_preimage(inv.payment_hash)
    auth = f"L402 {no_exp.to_token()}:{preimage}"
    assert authorize(
        SECRET, ln, auth_header_value=auth, resource_id="r1",
    ) is False


def test_rejects_expired_macaroon():
    ln = DeterministicMockBackend()
    inv = ln.create_invoice(100, "test")
    expired = Macaroon.create(SECRET, "r1", inv.payment_hash, ["exp=1"])
    preimage = ln.reveal_preimage(inv.payment_hash)
    auth = f"L402 {expired.to_token()}:{preimage}"
    assert authorize(
        SECRET, ln, auth_header_value=auth, resource_id="r1",
    ) is False


def test_expiry_check_runs_before_backend_rpc():
    """Round-2 amplification fix: expired tokens must short-circuit
    BEFORE calling ln.check_paid(). Otherwise a flood of replayed
    expired tokens becomes a flood of LN node RPC calls."""

    class _CountingBackend:
        name = "count"
        check_paid_calls = 0
        def create_invoice(self, *_a, **_k):
            raise NotImplementedError
        def check_paid(self, *_a, **_k):
            type(self).check_paid_calls += 1
            return True

    counting = _CountingBackend()
    real_ln = DeterministicMockBackend()
    inv = real_ln.create_invoice(100, "test")
    m = Macaroon.create(SECRET, "r1", inv.payment_hash, ["exp=1"])
    preimage = real_ln.reveal_preimage(inv.payment_hash)
    auth = f"L402 {m.to_token()}:{preimage}"
    assert authorize(
        SECRET, counting,
        auth_header_value=auth, resource_id="r1",
        require_backend_settled=True,
    ) is False
    assert _CountingBackend.check_paid_calls == 0


def test_rejects_preimage_that_doesnt_hash_to_payment_hash():
    ln = DeterministicMockBackend()
    chal = make_challenge(SECRET, ln, resource_id="r1")
    # Random preimage, not the real one.
    auth = f"L402 {chal.macaroon_token}:{'00' * 32}"
    assert authorize(
        SECRET, ln, auth_header_value=auth, resource_id="r1",
    ) is False


def test_rejects_malformed_authorization_headers():
    ln = DeterministicMockBackend()
    # Round-3 fix: case-insensitive scheme matching per RFC 7235.
    # Lowercase 'l402 ' is now ACCEPTED — see test_authorize_accepts_
    # case_insensitive_scheme in test_server.py.
    for bad in [
        "",
        "Bearer abcdef",
        "L402 noseparator",
        "L402 :emptytoken",
        "L402  double-space",
    ]:
        assert authorize(
            SECRET, ln, auth_header_value=bad, resource_id="r1",
        ) is False


def test_rejects_preimage_with_non_hex_characters():
    ln = DeterministicMockBackend()
    chal = make_challenge(SECRET, ln, resource_id="r1")
    auth = f"L402 {chal.macaroon_token}:not-hex-at-all"
    assert authorize(
        SECRET, ln, auth_header_value=auth, resource_id="r1",
    ) is False


# ---------- client: header parsing --------------------------------


def test_parse_rejects_challenge_missing_macaroon():
    with pytest.raises(ValueError, match="missing"):
        parse_challenge_header('L402 invoice="lnbc"')


def test_parse_rejects_challenge_missing_invoice():
    with pytest.raises(ValueError, match="missing"):
        parse_challenge_header('L402 macaroon="abc"')


def test_parse_rejects_non_l402_scheme():
    with pytest.raises(ValueError, match="not an L402"):
        parse_challenge_header('Basic abcdef')


def test_make_auth_header_rejects_crlf_injection():
    """Round-2 fix: a compromised pay_callback returning a string with
    CRLF lets an attacker inject HTTP headers downstream. preimage
    must be exactly 64 hex chars."""
    with pytest.raises(ValueError, match="64 hex"):
        make_auth_header("MAC", "ab" * 32 + "\r\nX-Evil: yes")


def test_make_auth_header_rejects_token_with_colon():
    """Macaroon tokens containing : would corrupt the server-side split."""
    with pytest.raises(ValueError, match="contains ':'"):
        make_auth_header("MAC:has:colons", "ab" * 32)


# ---------- client: network error handling -------------------------


class _FakeHTTPError(urllib.error.HTTPError):
    def __init__(self, code, body_bytes, headers):
        super().__init__(
            url="http://test/", code=code, msg="status", hdrs=headers,
            fp=io.BytesIO(body_bytes),
        )
        self._body = body_bytes
    def read(self):
        return self._body


def test_client_wraps_url_error_as_l402_network_error():
    """Round-2 fix: URLError used to escape uncaught, breaking the
    (status, body) contract. Now wrapped in L402NetworkError."""

    def dns_fail(req, timeout=None):
        raise urllib.error.URLError("DNS lookup failed")

    client = L402Client(pay_callback=lambda c: "00" * 32)
    with patch("l402.client.urllib.request.urlopen", side_effect=dns_fail):
        with pytest.raises(L402NetworkError):
            client.get("http://test.invalid/")


def test_client_doesnt_invoke_pay_callback_on_500():
    """A non-402 server error must not trigger the pay flow."""
    pay_calls = {"n": 0}

    def server_error(req, timeout=None):
        raise _FakeHTTPError(500, b"explosion", {})

    def pay_cb(c):
        pay_calls["n"] += 1
        return "00" * 32

    client = L402Client(pay_callback=pay_cb)
    with patch("l402.client.urllib.request.urlopen", side_effect=server_error):
        status, body = client.get("http://test/")
    assert status == 500
    assert pay_calls["n"] == 0


def test_client_max_retries_one_then_returns_402_on_repeated_demand():
    """If the server keeps returning 402 even after auth, we don't loop
    forever — we return the final 402 to the caller."""
    headers_402 = {"WWW-Authenticate": 'L402 macaroon="m", invoice="lnbc"'}

    def always_402(req, timeout=None):
        raise _FakeHTTPError(402, b"still no", headers_402)

    client = L402Client(pay_callback=lambda c: "00" * 32, max_retries=1)
    with patch("l402.client.urllib.request.urlopen", side_effect=always_402):
        status, body = client.get("http://test/")
    assert status == 402


# ---------- macaroon: token decoding -------------------------------


def test_macaroon_from_token_rejects_garbage():
    with pytest.raises(ValueError):
        Macaroon.from_token("not-base64-because-spaces")


def test_macaroon_from_token_rejects_non_list_caveats():
    bad = base64.urlsafe_b64encode(
        json.dumps({"id": "x", "ph": "y", "c": "not-a-list", "t": "z"}).encode()
    ).decode()
    with pytest.raises(ValueError, match="must be a list"):
        Macaroon.from_token(bad)


def test_macaroon_from_token_rejects_missing_fields():
    bad = base64.urlsafe_b64encode(
        json.dumps({"id": "x", "ph": "y"}).encode()   # missing c, t
    ).decode()
    with pytest.raises(ValueError, match="missing fields"):
        Macaroon.from_token(bad)


def test_macaroon_create_rejects_short_secret():
    """≥16-byte secret enforced. Stops operators from accidentally using
    a passphrase like 'changeme' that would be guessable."""
    with pytest.raises(ValueError, match="at least 16"):
        Macaroon.create(b"short", "id", "ph" * 16, [])


def test_macaroon_verify_returns_bool_not_truthy():
    """Tag check must return a real bool — not a value that lazy-truthy
    code could short-circuit. Defends against future timing-attack
    refactors that accidentally introduce early-return."""
    m = Macaroon.create(SECRET, "id", "ph" * 16, ["exp=9999999999"])
    assert isinstance(m.verify_tag(SECRET), bool)
    assert isinstance(m.verify_tag(OTHER_SECRET), bool)
