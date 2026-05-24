"""Server-side L402: issue challenges, authorize incoming requests.

Framework-agnostic — `make_challenge` returns a value object you can
hand to FastAPI / Flask / Django / Starlette / aiohttp / raw WSGI, and
`authorize` takes the literal Authorization header value plus the
expected resource id, returning a bool.

Wire flow:
  client → server  unauthenticated request
  server → client  HTTP 402 Payment Required
                   WWW-Authenticate: L402 macaroon="…", invoice="lnbc…"
  client → wallet  pays the invoice, receives preimage
  client → server  retry with Authorization: L402 <macaroon>:<preimage_hex>
  server           validates HMAC tag + preimage hash + caveat expiry
                   (optionally also checks backend settlement)
"""

from __future__ import annotations

import hashlib
import time

from .backends import LightningBackend
from .macaroon import Macaroon
from .types import L402Challenge


def make_challenge(
    secret: bytes,
    ln: LightningBackend,
    *,
    resource_id: str,
    amount_msat: int = 100,
    caveats: list[str] | None = None,
    expiry_seconds: int = 3600,
) -> L402Challenge:
    """Issue a fresh challenge for an unauthenticated request.

    Default caveats: resource=<resource_id> + exp=<now+expiry_seconds>.
    Every macaroon issued by this helper carries an `exp=` caveat so
    `authorize()`'s mandatory-expiry check has something to enforce.
    """
    inv = ln.create_invoice(amount_msat, memo=f"L402:{resource_id}")
    if caveats is None:
        caveats = [
            f"resource={resource_id}",
            f"exp={int(time.time()) + expiry_seconds}",
        ]
    elif not any(c.startswith("exp=") for c in caveats):
        # Caller-supplied caveats with no expiry: append our default.
        caveats = list(caveats) + [f"exp={int(time.time()) + expiry_seconds}"]
    m = Macaroon.create(
        secret=secret, identifier=resource_id,
        payment_hash=inv.payment_hash, caveats=caveats,
    )
    return L402Challenge(
        macaroon_token=m.to_token(),
        invoice_bolt11=inv.bolt11,
        payment_hash=inv.payment_hash,
    )


def authorize(
    secret: bytes,
    ln: LightningBackend,
    *,
    auth_header_value: str,
    resource_id: str,
    require_backend_settled: bool = False,
) -> bool:
    """Validate an `Authorization: L402 <macaroon>:<preimage>` header.

    Returns True iff ALL hold:
      1. Header is well-formed and starts with `L402 `.
      2. Macaroon HMAC tag verifies under `secret`.
      3. Macaroon identifier matches `resource_id`.
      4. SHA-256(preimage) == macaroon.payment_hash.
      5. Macaroon carries at least one `exp=<unix_ts>` caveat, and
         every such caveat is in the future.
      6. If `require_backend_settled=True`, the backend also reports
         the invoice as paid.

    Possession of a preimage that hashes to the macaroon's payment_hash
    is itself the cryptographic proof of payment in L402 — the preimage
    is only revealed by actually paying the invoice (or by being the
    issuer, which `secret` should prevent). `require_backend_settled`
    is opt-in defense in depth; it NEVER grants access on its own, only
    revokes it.
    """
    if not auth_header_value or not auth_header_value.startswith("L402 "):
        return False
    creds = auth_header_value[len("L402 "):]
    if ":" not in creds:
        return False
    token, preimage_hex = creds.split(":", 1)
    try:
        m = Macaroon.from_token(token)
    except ValueError:
        return False
    if not m.verify_tag(secret):
        return False
    if m.identifier != resource_id:
        return False
    try:
        preimage = bytes.fromhex(preimage_hex)
    except ValueError:
        return False
    if hashlib.sha256(preimage).hexdigest() != m.payment_hash:
        return False
    if require_backend_settled and not ln.check_paid(m.payment_hash):
        return False

    # Mandatory expiry: macaroon must carry at least one exp= caveat,
    # and every exp= must be in the future.
    now = int(time.time())
    saw_exp = False
    for c in m.caveats:
        if c.startswith("exp="):
            saw_exp = True
            try:
                if int(c.split("=", 1)[1]) < now:
                    return False
            except ValueError:
                return False
    if not saw_exp:
        return False
    return True
