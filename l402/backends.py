"""Lightning backends: the LightningBackend protocol + 4 implementations.

A backend speaks Lightning to your node (or stub) on behalf of the L402
server. Two methods, no surprises:

    create_invoice(amount_msat, memo) -> LnInvoice
    check_paid(payment_hash)         -> bool

Implementations:
  - DeterministicMockBackend  in-process, deterministic preimages, no LN
  - LndRestBackend            LND REST API + Grpc-Metadata-macaroon
  - PhoenixdBackend           Phoenixd HTTP + Basic auth
  - ClnRestBackend            Core Lightning REST plugin (rune auth)

All HTTP is via urllib.request (stdlib). Tests mock urlopen at the
patch boundary so the suite stays offline.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import ssl
import urllib.error
import urllib.request
from typing import Protocol

from .types import LnInvoice


# ---------- Protocol ----------------------------------------------


class LightningBackend(Protocol):
    """The two-method contract every backend implements."""
    name: str

    def create_invoice(self, amount_msat: int, memo: str) -> LnInvoice: ...
    def check_paid(self, payment_hash: str) -> bool: ...


def _make_ssl_context(cert_path: str | None) -> ssl.SSLContext | None:
    """Build an SSL context that trusts a specific self-signed cert.

    Returning None lets urllib fall back to default verification (good
    for nodes behind a real public CA).
    """
    if not cert_path:
        return None
    return ssl.create_default_context(cafile=cert_path)


# ---------- DeterministicMockBackend ------------------------------


class DeterministicMockBackend:
    """In-process mock with stored preimages so a demo can settle invoices.

    `bolt11` is a placeholder string, NOT a parseable BOLT-11 invoice —
    no real wallet can pay it. Tests + demos use `reveal_preimage()` to
    simulate settlement. Wire a real backend for production.
    """

    name = "mock"

    def __init__(self) -> None:
        self._issued: dict[str, tuple[LnInvoice, bytes]] = {}
        self._paid: set[str] = set()

    def create_invoice(self, amount_msat: int, memo: str) -> LnInvoice:
        preimage = os.urandom(32)
        payment_hash = hashlib.sha256(preimage).hexdigest()
        bolt11 = f"lnmock-{amount_msat}msat-{payment_hash[:16]}"
        inv = LnInvoice(
            bolt11=bolt11, payment_hash=payment_hash, amount_msat=amount_msat,
        )
        self._issued[payment_hash] = (inv, preimage)
        return inv

    def reveal_preimage(self, payment_hash: str) -> str:
        """Demo helper: pretend the invoice was paid, return preimage hex."""
        inv, preimage = self._issued[payment_hash]
        self._paid.add(payment_hash)
        return preimage.hex()

    def check_paid(self, payment_hash: str) -> bool:
        return payment_hash in self._paid


# ---------- LndRestBackend ----------------------------------------


class LndRestBackend:
    """LND REST API (https://api.lightning.community/rest/).

    Endpoints:
      POST /v1/invoices            create invoice
      GET  /v1/invoice/{r_hash}    query settlement state

    Auth: hex-encoded macaroon in `Grpc-Metadata-macaroon` header.
    Tip: `xxd -ps -u -c 1000 ~/.lnd/data/chain/bitcoin/.../admin.macaroon`
    """

    name = "lnd"

    def __init__(
        self,
        url: str,
        macaroon_hex: str,
        tls_cert_path: str | None = None,
        timeout_seconds: float = 15.0,
    ) -> None:
        self.url = url.rstrip("/")
        self.macaroon_hex = macaroon_hex
        self.timeout = timeout_seconds
        self._ssl_ctx = _make_ssl_context(tls_cert_path)

    def _request(self, method: str, path: str, body: dict | None = None) -> dict:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(
            f"{self.url}{path}", data=data, method=method,
            headers={
                "Grpc-Metadata-macaroon": self.macaroon_hex,
                "Content-Type": "application/json",
            },
        )
        with urllib.request.urlopen(
            req, timeout=self.timeout, context=self._ssl_ctx,
        ) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def create_invoice(self, amount_msat: int, memo: str) -> LnInvoice:
        resp = self._request("POST", "/v1/invoices", {
            "value_msat": str(amount_msat),
            "memo": memo,
            "expiry": "3600",
        })
        r_hash_hex = base64.b64decode(resp["r_hash"]).hex()
        return LnInvoice(
            bolt11=resp["payment_request"],
            payment_hash=r_hash_hex,
            amount_msat=amount_msat,
        )

    def check_paid(self, payment_hash: str) -> bool:
        try:
            resp = self._request("GET", f"/v1/invoice/{payment_hash}")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return False
            raise
        return resp.get("state") == "SETTLED" or bool(resp.get("settled"))


# ---------- PhoenixdBackend ---------------------------------------


class PhoenixdBackend:
    """Phoenixd HTTP API (https://phoenix.acinq.co/server/api).

    Endpoints:
      POST /createinvoice                  amountSat + description form body
      GET  /payments/incoming/{paymentHash}

    Auth: HTTP Basic with empty username + http-password from
    ~/.phoenix/phoenix.conf.
    """

    name = "phoenixd"

    def __init__(
        self,
        url: str,
        password: str,
        timeout_seconds: float = 15.0,
    ) -> None:
        self.url = url.rstrip("/")
        self.password = password
        self.timeout = timeout_seconds
        token = base64.b64encode(f":{password}".encode()).decode("ascii")
        self._auth_header = f"Basic {token}"

    def _request(
        self, method: str, path: str, form_body: dict | None = None,
    ) -> dict:
        url = f"{self.url}{path}"
        data = None
        headers = {"Authorization": self._auth_header}
        if form_body is not None:
            data = "&".join(
                f"{k}={urllib.request.quote(str(v))}"
                for k, v in form_body.items()
            ).encode("ascii")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def create_invoice(self, amount_msat: int, memo: str) -> LnInvoice:
        # Phoenixd takes amountSat; round UP so we never undercharge.
        amount_sat = max(1, (amount_msat + 999) // 1000)
        resp = self._request("POST", "/createinvoice", {
            "amountSat": amount_sat,
            "description": memo,
        })
        return LnInvoice(
            bolt11=resp["serialized"],
            payment_hash=resp["paymentHash"],
            amount_msat=amount_sat * 1000,
        )

    def check_paid(self, payment_hash: str) -> bool:
        try:
            resp = self._request("GET", f"/payments/incoming/{payment_hash}")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return False
            raise
        return bool(resp.get("isPaid"))


# ---------- ClnRestBackend ----------------------------------------


class ClnRestBackend:
    """Core Lightning REST plugin (https://github.com/Ride-The-Lightning/c-lightning-REST,
    or the modern `clnrest` plugin shipped with CLN itself).

    Endpoints (modern clnrest):
      POST /v1/invoice                          {amount_msat, label, description}
      GET  /v1/listinvoices?label=<label>       check status

    Auth: rune in `Rune` header (modern clnrest) or macaroon in
    `Grpc-Metadata-macaroon` (legacy c-lightning-REST). We default to
    rune since that's the supported path going forward.
    """

    name = "cln"

    def __init__(
        self,
        url: str,
        rune: str,
        tls_cert_path: str | None = None,
        timeout_seconds: float = 15.0,
    ) -> None:
        self.url = url.rstrip("/")
        self.rune = rune
        self.timeout = timeout_seconds
        self._ssl_ctx = _make_ssl_context(tls_cert_path)
        # CLN's `label` is the only durable way to look an invoice back
        # up; we track payment_hash → label so check_paid() works.
        self._label_for: dict[str, str] = {}

    def _request(self, method: str, path: str, body: dict | None = None) -> dict:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(
            f"{self.url}{path}", data=data, method=method,
            headers={
                "Rune": self.rune,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        with urllib.request.urlopen(
            req, timeout=self.timeout, context=self._ssl_ctx,
        ) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def create_invoice(self, amount_msat: int, memo: str) -> LnInvoice:
        # CLN's `label` must be unique per invoice. We mint one from the
        # memo + a random suffix so concurrent callers don't collide.
        label = f"l402-{memo[:32]}-{os.urandom(6).hex()}"
        resp = self._request("POST", "/v1/invoice", {
            "amount_msat": amount_msat,
            "label": label,
            "description": memo,
        })
        payment_hash = resp["payment_hash"]
        self._label_for[payment_hash] = label
        return LnInvoice(
            bolt11=resp["bolt11"],
            payment_hash=payment_hash,
            amount_msat=amount_msat,
        )

    def check_paid(self, payment_hash: str) -> bool:
        label = self._label_for.get(payment_hash)
        if label is None:
            # Issuer-instance lost the label (process restart, etc.).
            # Fall back to filtering by payment_hash; some clnrest
            # versions support this directly.
            try:
                resp = self._request(
                    "GET", f"/v1/listinvoices?payment_hash={payment_hash}",
                )
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    return False
                raise
        else:
            try:
                resp = self._request("GET", f"/v1/listinvoices?label={label}")
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    return False
                raise
        for inv in resp.get("invoices", []):
            if inv.get("payment_hash") == payment_hash:
                return inv.get("status") == "paid"
        return False
