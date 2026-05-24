"""Server-side: make_challenge and authorize."""

import time

import pytest

from l402.backends import DeterministicMockBackend
from l402.macaroon import Macaroon
from l402.server import authorize, make_challenge


SECRET = b"test-secret-32-bytes-or-whatever"


def test_make_challenge_includes_exp_by_default():
    ln = DeterministicMockBackend()
    chal = make_challenge(SECRET, ln, resource_id="premium:m1", amount_msat=100)
    m = Macaroon.from_token(chal.macaroon_token)
    assert any(c.startswith("exp=") for c in m.caveats)
    assert any(c == "resource=premium:m1" for c in m.caveats)


def test_make_challenge_appends_exp_when_caller_caveats_lack_one():
    ln = DeterministicMockBackend()
    chal = make_challenge(
        SECRET, ln, resource_id="r1",
        caveats=["custom=ok"],   # no exp
    )
    m = Macaroon.from_token(chal.macaroon_token)
    assert any(c == "custom=ok" for c in m.caveats)
    assert any(c.startswith("exp=") for c in m.caveats)


def test_make_challenge_preserves_caller_exp():
    ln = DeterministicMockBackend()
    chal = make_challenge(
        SECRET, ln, resource_id="r1",
        caveats=["exp=9999999999"],  # caller-supplied exp
    )
    m = Macaroon.from_token(chal.macaroon_token)
    exp_caveats = [c for c in m.caveats if c.startswith("exp=")]
    assert exp_caveats == ["exp=9999999999"]


def test_challenge_header_format():
    ln = DeterministicMockBackend()
    chal = make_challenge(SECRET, ln, resource_id="r1")
    h = chal.header_value()
    assert h.startswith("L402 ")
    assert 'macaroon="' in h
    assert 'invoice="' in h


def test_authorize_happy_path():
    ln = DeterministicMockBackend()
    chal = make_challenge(SECRET, ln, resource_id="r1", amount_msat=100)
    preimage_hex = ln.reveal_preimage(chal.payment_hash)
    auth = f"L402 {chal.macaroon_token}:{preimage_hex}"
    assert authorize(
        SECRET, ln, auth_header_value=auth, resource_id="r1",
    ) is True


def test_authorize_rejects_wrong_preimage():
    ln = DeterministicMockBackend()
    chal = make_challenge(SECRET, ln, resource_id="r1")
    auth = f"L402 {chal.macaroon_token}:{'00' * 32}"
    assert authorize(
        SECRET, ln, auth_header_value=auth, resource_id="r1",
    ) is False


def test_authorize_rejects_wrong_resource():
    ln = DeterministicMockBackend()
    chal = make_challenge(SECRET, ln, resource_id="r1")
    preimage_hex = ln.reveal_preimage(chal.payment_hash)
    auth = f"L402 {chal.macaroon_token}:{preimage_hex}"
    assert authorize(
        SECRET, ln, auth_header_value=auth, resource_id="r2",
    ) is False


def test_authorize_rejects_wrong_secret():
    ln = DeterministicMockBackend()
    chal = make_challenge(SECRET, ln, resource_id="r1")
    preimage_hex = ln.reveal_preimage(chal.payment_hash)
    auth = f"L402 {chal.macaroon_token}:{preimage_hex}"
    other_secret = b"different-secret-32-bytes-pad-yy"
    assert authorize(
        other_secret, ln, auth_header_value=auth, resource_id="r1",
    ) is False


def test_authorize_rejects_malformed_headers():
    ln = DeterministicMockBackend()
    for bad in ["", "Bearer abc", "L402 noseparator", "L402 :emptytoken",
                "l402 lowercase-prefix"]:
        assert authorize(
            SECRET, ln, auth_header_value=bad, resource_id="r1",
        ) is False


def test_authorize_rejects_macaroon_without_exp_caveat():
    """Mandatory exp= caveat: macaroon with empty caveats is rejected."""
    ln = DeterministicMockBackend()
    inv = ln.create_invoice(100, "test")
    # Hand-craft a macaroon with NO exp caveat.
    m = Macaroon.create(SECRET, "r1", inv.payment_hash, [])
    preimage = ln.reveal_preimage(inv.payment_hash)
    auth = f"L402 {m.to_token()}:{preimage}"
    assert authorize(
        SECRET, ln, auth_header_value=auth, resource_id="r1",
    ) is False


def test_authorize_rejects_expired_macaroon():
    ln = DeterministicMockBackend()
    inv = ln.create_invoice(100, "test")
    m = Macaroon.create(
        SECRET, "r1", inv.payment_hash, ["exp=1"],  # year 1970
    )
    preimage = ln.reveal_preimage(inv.payment_hash)
    auth = f"L402 {m.to_token()}:{preimage}"
    assert authorize(
        SECRET, ln, auth_header_value=auth, resource_id="r1",
    ) is False


def test_authorize_rejects_malformed_exp_value():
    ln = DeterministicMockBackend()
    inv = ln.create_invoice(100, "test")
    m = Macaroon.create(
        SECRET, "r1", inv.payment_hash, ["exp=not-a-number"],
    )
    preimage = ln.reveal_preimage(inv.payment_hash)
    auth = f"L402 {m.to_token()}:{preimage}"
    assert authorize(
        SECRET, ln, auth_header_value=auth, resource_id="r1",
    ) is False


def test_authorize_require_backend_settled_paths():
    """require_backend_settled=True should reject unpaid invoices."""
    ln = DeterministicMockBackend()
    chal = make_challenge(SECRET, ln, resource_id="r1")
    preimage_hex = ln.reveal_preimage(chal.payment_hash)  # marks paid
    auth = f"L402 {chal.macaroon_token}:{preimage_hex}"
    assert authorize(
        SECRET, ln, auth_header_value=auth, resource_id="r1",
        require_backend_settled=True,
    ) is True

    # Now a different challenge that we DON'T settle.
    chal2 = make_challenge(SECRET, ln, resource_id="r2")
    # Cheat: pull preimage out of the backend's internals without
    # marking paid (simulating a real backend lag).
    preimage_b = ln._issued[chal2.payment_hash][1]
    auth2 = f"L402 {chal2.macaroon_token}:{preimage_b.hex()}"
    # Without require: passes (preimage is valid).
    assert authorize(SECRET, ln, auth_header_value=auth2, resource_id="r2") is True
    # With require: rejected.
    assert authorize(
        SECRET, ln, auth_header_value=auth2, resource_id="r2",
        require_backend_settled=True,
    ) is False
