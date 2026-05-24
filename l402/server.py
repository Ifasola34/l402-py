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
import hmac
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
    else:
        # Caller supplied at least one exp= — validate it's parseable
        # so the macaroon we issue isn't born already-unusable. Without
        # this check, caveats=["exp=tomorrow"] would mint a token that
        # authorize() silently rejects later with no diagnostic.
        for c in caveats:
            if c.startswith("exp="):
                try:
                    int(c.split("=", 1)[1])
                except ValueError:
                    raise ValueError(
                        f"caveat {c!r} has a malformed exp= value; "
                        "value must be an integer unix timestamp"
                    )
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
    # RFC 7235 mandates case-insensitive auth schemes. Accept "L402 ",
    # "l402 ", "L402 " etc. equally. We compare the first 5 chars
    # case-insensitively and require the trailing space.
    if (
        not auth_header_value
        or len(auth_header_value) < 5
        or auth_header_value[:4].lower() != "l402"
        or auth_header_value[4] != " "
    ):
        return False
    creds = auth_header_value[5:]
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
    # Constant-time hex compare to match the hardening posture of the
    # earlier verify_tag check. Practical preimage second-preimage
    # attacks on SHA-256 are infeasible, but consistency matters.
    if not hmac.compare_digest(
        hashlib.sha256(preimage).hexdigest(), m.payment_hash,
    ):
        return False
    # Mandatory expiry: macaroon must carry at least one exp= caveat,
    # and every exp= must be in the future. This MUST run BEFORE the
    # optional backend settlement check so a flood of replayed expired
    # tokens cannot amplify into a flood of LN node RPC calls.
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

    if require_backend_settled and not ln.check_paid(m.payment_hash):
        return False

    return True
