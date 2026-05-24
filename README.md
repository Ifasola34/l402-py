# l402-py

**L402 (Lightning paywall) for Python — both sides of the protocol.**

L402 is the Lightning-native HTTP 402 protocol: client hits an endpoint, server returns `402 Payment Required` with a Lightning invoice + opaque macaroon, client pays the invoice, retries with the preimage as proof. No accounts. No API keys. No KYC. Just Bitcoin.

This library is what you reach for when you want to add an L402 paywall to your API or consume someone else's L402-gated endpoint from Python.

---

## What's in the box

| | |
|---|---|
| **Server side** | `make_challenge`, `authorize` — issue 402 responses, validate `Authorization: L402 ...` headers. Framework-agnostic; drop into FastAPI, Flask, Django, Starlette, aiohttp, raw WSGI. |
| **Client side** | `parse_challenge_header`, `make_auth_header`, `L402Client` — parse 402 responses, build retry headers, or use the high-level client to handle the full dance automatically. |
| **Backends** | `DeterministicMockBackend` (in-process, for tests), `LndRestBackend` (LND REST API), `PhoenixdBackend` (Phoenixd HTTP), `ClnRestBackend` (Core Lightning REST). |
| **Macaroons** | HMAC-SHA256-tagged authority tokens with explicit caveat enforcement. Mandatory `exp=` caveat on every macaroon — no infinite-lifetime tokens. |
| **CLI** | `l402 challenge` / `l402 verify` / `l402 decode-challenge` / `l402 pay` for debugging integrations. |

Zero runtime deps outside the standard library + `click` + `rich`. No `requests`, no `httpx`, no `cryptography`. Drop it into any Python project without dependency conflicts.

---

## Install

Requires Python 3.10+.

```bash
pip install git+https://github.com/Ifasola34/l402-py.git
```

(PyPI release tracked separately; `pip install l402-py` will work once published.)

---

## The protocol in one diagram

```
   ┌──────────┐                                  ┌─────────────┐
   │  client  │   GET /premium                   │   server    │
   │          │ ───────────────────────────────► │             │
   │          │                                  │  no auth    │
   │          │   402 Payment Required           │     ▼       │
   │          │   WWW-Authenticate: L402         │  make_      │
   │          │       macaroon="MAC",            │  challenge  │
   │          │       invoice="lnbc1p…"          │             │
   │          │ ◄─────────────────────────────── │             │
   │   ▼      │                                  │             │
   │  pay LN  │                                  │             │
   │   ▼      │                                  │             │
   │ preimage │   GET /premium                   │             │
   │          │   Authorization: L402            │             │
   │          │       MAC:<preimage_hex>         │             │
   │          │ ───────────────────────────────► │             │
   │          │                                  │  authorize  │
   │          │   200 OK + payload               │     ▼       │
   │          │ ◄─────────────────────────────── │   serve!    │
   └──────────┘                                  └─────────────┘
```

The macaroon is **bound to the invoice's payment_hash via HMAC**. Possession of a preimage that hashes to that payment_hash IS the cryptographic proof of payment — only paying the invoice reveals it.

---

## Server example (framework-agnostic)

```python
from l402 import make_challenge, authorize, DeterministicMockBackend

SECRET = b"32-bytes-of-server-only-entropy!"
ln = DeterministicMockBackend()   # swap for LndRestBackend / PhoenixdBackend / ClnRestBackend in prod

def serve_premium(request):
    auth = request.headers.get("Authorization")
    if auth and authorize(SECRET, ln,
                          auth_header_value=auth,
                          resource_id="api:premium"):
        return 200, {"data": "🚀"}
    # Issue a challenge.
    chal = make_challenge(SECRET, ln, resource_id="api:premium", amount_msat=1000)
    return 402, {
        "headers": {"WWW-Authenticate": chal.header_value()},
        "body": {"error": "Payment Required",
                 "macaroon": chal.macaroon_token,
                 "invoice": chal.invoice_bolt11,
                 "payment_hash": chal.payment_hash},
    }
```

### FastAPI

```python
from fastapi import FastAPI, Header, Request, Response
from fastapi.responses import JSONResponse

app = FastAPI()

@app.get("/premium")
def premium(request: Request, authorization: str | None = Header(default=None)):
    if authorization and authorize(SECRET, ln,
                                   auth_header_value=authorization,
                                   resource_id="api:premium"):
        return {"data": "🚀"}
    chal = make_challenge(SECRET, ln, resource_id="api:premium", amount_msat=1000)
    return JSONResponse(
        {"error": "Payment Required", "invoice": chal.invoice_bolt11},
        status_code=402,
        headers={"WWW-Authenticate": chal.header_value()},
    )
```

---

## Client example

```python
from l402 import L402Client, ParsedChallenge

def pay_via_my_wallet(challenge: ParsedChallenge) -> str:
    # Decode challenge.invoice_bolt11, pay via your wallet, return preimage hex.
    return my_wallet.pay_and_get_preimage(challenge.invoice_bolt11)

client = L402Client(pay_callback=pay_via_my_wallet)
status, body = client.get("https://api.example.com/premium")
# Library handles 402 → pay → retry transparently. You get (200, body).
```

Or use the low-level helpers with your existing HTTP client:

```python
from l402 import parse_challenge_header, make_auth_header
import requests

r = requests.get("https://api.example.com/premium")
if r.status_code == 402:
    chal = parse_challenge_header(r.headers["WWW-Authenticate"])
    preimage_hex = my_wallet.pay(chal.invoice_bolt11)
    r = requests.get(
        "https://api.example.com/premium",
        headers={"Authorization": make_auth_header(chal.macaroon_token, preimage_hex)},
    )
```

---

## Backends

| | Use this when |
|---|---|
| `DeterministicMockBackend()` | Tests, local dev, demos. In-process; `reveal_preimage()` settles invoices without a node. |
| `LndRestBackend(url, macaroon_hex, tls_cert_path)` | You run LND. Set `macaroon_hex` from `xxd -ps -u -c 1000 admin.macaroon`. |
| `PhoenixdBackend(url, password)` | You run Phoenixd (ACINQ's lightweight self-custodial node). `password` is `http-password` from `~/.phoenix/phoenix.conf`. |
| `ClnRestBackend(url, rune, tls_cert_path)` | You run Core Lightning with the `clnrest` plugin. `rune` is from `lightning-cli createrune`. |

All four implement the same `LightningBackend` protocol:

```python
class LightningBackend(Protocol):
    name: str
    def create_invoice(self, amount_msat: int, memo: str) -> LnInvoice: ...
    def check_paid(self, payment_hash: str) -> bool: ...
```

Roll your own for Eclair, LDK-Node, LNbits, BTCPay Server, or anything else — implement two methods.

---

## Security notes

- **Macaroons require an `exp=` caveat.** `authorize()` rejects any macaroon without one. `make_challenge()` automatically adds one (default 3600s).
- **HMAC keys must be ≥16 bytes.** `Macaroon.create()` raises on shorter secrets. 32+ bytes recommended.
- **`require_backend_settled=True`** opt-in flag adds defense-in-depth: even with a valid preimage, the LN backend must also report the invoice as settled. Useful for backends with strict revocation/refund semantics.
- **`require_backend_settled=False`** (default) trusts the preimage cryptographically. Preimage knowledge IS payment proof in L402; the backend check is belt-and-suspenders.

---

## CLI

```bash
# Issue a fresh challenge (mock backend, useful for fixtures)
l402 challenge --resource api:premium --secret hex:$(openssl rand -hex 32)

# Decode a WWW-Authenticate header someone handed you
l402 decode-challenge 'L402 macaroon="…", invoice="lnbc1p…"'

# Verify an Authorization header against a known secret
l402 verify --auth-header 'L402 MAC:preimage_hex' \
            --resource api:premium \
            --secret hex:abcd...

# Do the L402 dance against a real URL (preimage from file, you pay externally)
l402 pay https://api.example.com/premium --preimage-from preimage.hex
```

---

## Tests

```bash
$ pytest -v
55 passed in 0.11s
```

All network calls (LND/Phoenixd/CLN HTTP) are mocked, so the suite runs fully offline. Coverage:

- **Macaroon (9):** HMAC roundtrip, wrong-secret/wrong-caveat rejection, short-secret rejection, token roundtrip, malformed-token rejection, missing-field rejection, non-list-caveat rejection, constant-time check.
- **Server (13):** challenge includes exp caveat by default, exp appended when caller omits it, caller exp preserved, header format, happy-path authorize, wrong preimage/resource/secret rejected, malformed headers rejected, no-exp macaroon rejected, expired macaroon rejected, malformed exp value rejected, `require_backend_settled` both paths.
- **Client (12):** quoted + unquoted parsing, param order tolerance, case insensitivity, whitespace tolerance, non-L402 rejection, missing-field rejection, header builder, colon-in-token rejection, full L402Client dance with mocked HTTP, max-retries respected, non-402 errors propagate without invoking pay_callback.
- **Backends (14):** mock create + reveal + check_paid; LND request shape + settled/open/404/non-404 paths; Phoenixd msat→sat rounding + Basic auth + check_paid + 404; CLN request shape + check_paid by label + unpaid + missing-label fallback to hash filter.
- **CLI (7):** challenge runs, secret warning, decode-challenge pretty-prints, decode rejects non-L402, verify authorizes + rejects, short-passphrase rejection.

---

## Why a separate library

L402 logic shouldn't be locked inside any single L402-using project. Pulling out the protocol primitives into their own package means:

- **Anyone building a paid API** can wire L402 in three imports.
- **Anyone consuming a paid API** can integrate without re-implementing macaroon parsing.
- **The protocol surface stays auditable.** This whole repo is ~1,500 lines including tests. You can read it in a sitting and know exactly what's HMAC'd, when expiry is enforced, and where preimages are checked.

L402 already has a Go reference implementation (Lightning Labs' `aperture`) and a TypeScript one. Python has had partial implementations scattered across other paywall projects but no single clean library. This is that library.

---

## License

MIT — see [`LICENSE`](LICENSE).
