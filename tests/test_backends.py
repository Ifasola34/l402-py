"""Backends: mock (in-process) + LND + Phoenixd + CLN (all HTTP mocked)."""

import base64
import io
import json
import urllib.error
from unittest.mock import MagicMock, patch

import pytest

from l402.backends import (
    ClnRestBackend,
    DeterministicMockBackend,
    LndRestBackend,
    PhoenixdBackend,
)


class _FakeResp(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): self.close()


# ---------- DeterministicMockBackend ------------------------------


def test_mock_create_invoice_returns_random_hash():
    b = DeterministicMockBackend()
    inv1 = b.create_invoice(100, "x")
    inv2 = b.create_invoice(100, "x")
    assert inv1.payment_hash != inv2.payment_hash
    assert len(inv1.payment_hash) == 64
    assert inv1.amount_msat == 100
    assert inv1.bolt11.startswith("lnmock-")


def test_mock_check_paid_flips_after_reveal():
    b = DeterministicMockBackend()
    inv = b.create_invoice(100, "x")
    assert b.check_paid(inv.payment_hash) is False
    preimage = b.reveal_preimage(inv.payment_hash)
    assert b.check_paid(inv.payment_hash) is True
    # Preimage hashes correctly.
    import hashlib
    assert hashlib.sha256(bytes.fromhex(preimage)).hexdigest() == inv.payment_hash


# ---------- LndRestBackend ----------------------------------------


def test_lnd_create_invoice_shape():
    r_hash = bytes.fromhex("aa" * 32)
    resp = json.dumps({
        "r_hash": base64.b64encode(r_hash).decode(),
        "payment_request": "lnbc1pmocked",
    }).encode()
    with patch("l402.backends.urllib.request.urlopen",
               return_value=_FakeResp(resp)) as mock_open:
        b = LndRestBackend(url="https://node:8080", macaroon_hex="cafe")
        inv = b.create_invoice(1000, "test")
    sent = mock_open.call_args[0][0]
    assert sent.full_url == "https://node:8080/v1/invoices"
    assert sent.headers.get("Grpc-metadata-macaroon") == "cafe"
    body = json.loads(sent.data.decode())
    assert body == {"value_msat": "1000", "memo": "test", "expiry": "3600"}
    assert inv.payment_hash == "aa" * 32


def test_lnd_check_paid_settled_and_open():
    settled = json.dumps({"state": "SETTLED", "settled": True}).encode()
    open_ = json.dumps({"state": "OPEN", "settled": False}).encode()
    with patch("l402.backends.urllib.request.urlopen",
               return_value=_FakeResp(settled)):
        assert LndRestBackend("https://n", "ca").check_paid("aa" * 32) is True
    with patch("l402.backends.urllib.request.urlopen",
               return_value=_FakeResp(open_)):
        assert LndRestBackend("https://n", "ca").check_paid("aa" * 32) is False


def test_lnd_check_paid_404_is_unpaid():
    err = urllib.error.HTTPError(
        url="https://n/v1/invoice/00", code=404, msg="Not Found",
        hdrs={}, fp=io.BytesIO(b"{}"),
    )
    with patch("l402.backends.urllib.request.urlopen", side_effect=err):
        assert LndRestBackend("https://n", "ca").check_paid("00" * 32) is False


def test_lnd_check_paid_other_http_error_propagates():
    err = urllib.error.HTTPError(
        url="https://n", code=500, msg="boom",
        hdrs={}, fp=io.BytesIO(b"{}"),
    )
    with patch("l402.backends.urllib.request.urlopen", side_effect=err):
        with pytest.raises(urllib.error.HTTPError):
            LndRestBackend("https://n", "ca").check_paid("00" * 32)


# ---------- PhoenixdBackend ---------------------------------------


def test_phoenixd_create_invoice_rounds_msat_up_to_sat():
    resp = json.dumps({
        "serialized": "lnbc1psmoothmocked",
        "paymentHash": "bb" * 32,
    }).encode()
    with patch("l402.backends.urllib.request.urlopen",
               return_value=_FakeResp(resp)) as mock_open:
        b = PhoenixdBackend(url="http://127.0.0.1:9740", password="pw")
        inv = b.create_invoice(2500, "memo with spaces")
    sent = mock_open.call_args[0][0]
    # 2500 msat -> 3 sat (round up).
    body = sent.data.decode()
    assert "amountSat=3" in body
    assert "description=memo%20with%20spaces" in body
    assert inv.amount_msat == 3000


def test_phoenixd_basic_auth_header():
    resp = json.dumps({"serialized": "lnbc", "paymentHash": "00" * 32}).encode()
    with patch("l402.backends.urllib.request.urlopen",
               return_value=_FakeResp(resp)) as mock_open:
        PhoenixdBackend("http://x", "hunter2").create_invoice(100, "x")
    sent = mock_open.call_args[0][0]
    expected = "Basic " + base64.b64encode(b":hunter2").decode()
    assert sent.headers.get("Authorization") == expected


def test_phoenixd_check_paid():
    paid = json.dumps({"isPaid": True}).encode()
    unpaid = json.dumps({"isPaid": False}).encode()
    with patch("l402.backends.urllib.request.urlopen",
               return_value=_FakeResp(paid)):
        assert PhoenixdBackend("http://x", "p").check_paid("bb" * 32) is True
    with patch("l402.backends.urllib.request.urlopen",
               return_value=_FakeResp(unpaid)):
        assert PhoenixdBackend("http://x", "p").check_paid("bb" * 32) is False


def test_phoenixd_check_paid_404_is_unpaid():
    err = urllib.error.HTTPError(
        url="http://x/payments/incoming/00", code=404, msg="Not Found",
        hdrs={}, fp=io.BytesIO(b"{}"),
    )
    with patch("l402.backends.urllib.request.urlopen", side_effect=err):
        assert PhoenixdBackend("http://x", "p").check_paid("00" * 32) is False


# ---------- ClnRestBackend ----------------------------------------


def test_cln_create_invoice_sends_correct_request():
    resp = json.dumps({
        "bolt11": "lnbc1pcln",
        "payment_hash": "cc" * 32,
    }).encode()
    with patch("l402.backends.urllib.request.urlopen",
               return_value=_FakeResp(resp)) as mock_open:
        b = ClnRestBackend(url="https://cln:3010", rune="RUNE123")
        inv = b.create_invoice(50000, "demo")
    sent = mock_open.call_args[0][0]
    assert sent.full_url == "https://cln:3010/v1/invoice"
    assert sent.headers.get("Rune") == "RUNE123"
    body = json.loads(sent.data.decode())
    assert body["amount_msat"] == 50000
    assert body["description"] == "demo"
    assert body["label"].startswith("l402-demo-")
    assert inv.payment_hash == "cc" * 32
    # Backend remembers the label so check_paid can look it up.
    assert b._label_for["cc" * 32] == body["label"]


def test_cln_check_paid_by_label():
    """After create_invoice the backend knows the label; uses it on check."""
    create_resp = json.dumps({
        "bolt11": "lnbc",
        "payment_hash": "dd" * 32,
    }).encode()
    list_resp = json.dumps({
        "invoices": [{"payment_hash": "dd" * 32, "status": "paid"}],
    }).encode()

    responses = iter([_FakeResp(create_resp), _FakeResp(list_resp)])
    with patch("l402.backends.urllib.request.urlopen",
               side_effect=lambda req, timeout=None, context=None: next(responses)) as mock_open:
        b = ClnRestBackend(url="https://cln", rune="R")
        b.create_invoice(100, "x")
        ok = b.check_paid("dd" * 32)
    assert ok is True
    second_req = mock_open.call_args_list[1][0][0]
    assert "?label=l402-x-" in second_req.full_url


def test_cln_check_paid_returns_false_for_unpaid():
    list_resp = json.dumps({
        "invoices": [{"payment_hash": "ee" * 32, "status": "unpaid"}],
    }).encode()
    b = ClnRestBackend(url="https://cln", rune="R")
    b._label_for["ee" * 32] = "label-ee"  # pretend we issued it
    with patch("l402.backends.urllib.request.urlopen",
               return_value=_FakeResp(list_resp)):
        assert b.check_paid("ee" * 32) is False


def test_cln_check_paid_handles_missing_label_via_hash_filter():
    """If the backend instance never issued this invoice, fall back to
    filtering by payment_hash directly."""
    list_resp = json.dumps({
        "invoices": [{"payment_hash": "ff" * 32, "status": "paid"}],
    }).encode()
    b = ClnRestBackend(url="https://cln", rune="R")
    with patch("l402.backends.urllib.request.urlopen",
               return_value=_FakeResp(list_resp)) as mock_open:
        ok = b.check_paid("ff" * 32)
    assert ok is True
    req = mock_open.call_args[0][0]
    assert "?payment_hash=ff" in req.full_url
