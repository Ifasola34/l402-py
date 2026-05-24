"""Minimal macaroon implementation for L402.

This is NOT bit-compatible with libmacaroons (the canonical C
implementation). It is semantically equivalent for the L402 use case:
an authority token whose authenticity tag is computed against a
server-only HMAC key, and whose caveats narrow access.

Why reimplement instead of pulling in libmacaroons?
  - libmacaroons is a heavyweight C dep with binding headaches across
    platforms (macOS / Linux / Alpine all behave differently)
  - L402 needs ~5% of the libmacaroons feature set: tag verification,
    caveat enforcement, base64 token transport
  - Anyone auditing this paywall reads ~80 lines of Python, not a
    thousand lines of cmake + C

The wire format is base64-URL of a sorted-JSON object with fields:
  id  — opaque server-meaningful identifier (resource id, route, etc.)
  ph  — payment hash hex (binds the token to a specific LN invoice)
  c   — list of caveat strings ("resource=premium", "exp=1799999999", …)
  t   — base64 HMAC-SHA256 tag over a canonical encoding of {id, ph, c}
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass


@dataclass(frozen=True)
class Macaroon:
    """A tiny L402-flavored macaroon.

    Frozen so the dataclass fields can't be reassigned, but note that
    `caveats: list[str]` is itself mutable — append/pop would mutate
    in-place. The HMAC tag binds the caveat list at creation, so any
    mid-flight mutation breaks `verify_tag()`.
    """

    identifier: str
    payment_hash: str
    caveats: list[str]
    tag: str   # base64

    @classmethod
    def create(
        cls,
        secret: bytes,
        identifier: str,
        payment_hash: str,
        caveats: list[str],
    ) -> "Macaroon":
        if not isinstance(secret, (bytes, bytearray)) or len(secret) < 16:
            raise ValueError(
                "secret must be at least 16 bytes (32+ recommended)"
            )
        msg = json.dumps(
            {"id": identifier, "ph": payment_hash, "c": list(caveats)},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        tag = base64.b64encode(
            hmac.new(secret, msg, hashlib.sha256).digest()
        ).decode("ascii")
        return cls(identifier, payment_hash, list(caveats), tag)

    def verify_tag(self, secret: bytes) -> bool:
        """Constant-time tag check. Returns False on any malformed input."""
        try:
            expected = Macaroon.create(
                secret, self.identifier, self.payment_hash, self.caveats,
            )
        except ValueError:
            return False
        return hmac.compare_digest(expected.tag, self.tag)

    def to_token(self) -> str:
        """URL-safe base64 of the JSON-encoded macaroon."""
        return base64.urlsafe_b64encode(
            json.dumps(
                {
                    "id": self.identifier,
                    "ph": self.payment_hash,
                    "c": list(self.caveats),
                    "t": self.tag,
                }
            ).encode("utf-8")
        ).decode("ascii")

    @classmethod
    def from_token(cls, token: str) -> "Macaroon":
        """Inverse of to_token. Raises ValueError on malformed input."""
        try:
            raw = base64.urlsafe_b64decode(token.encode("ascii"))
            d = json.loads(raw)
        except (ValueError, json.JSONDecodeError) as e:
            raise ValueError(f"malformed macaroon token: {e}")
        required = {"id", "ph", "c", "t"}
        if not required.issubset(d.keys()):
            raise ValueError(
                f"macaroon token missing fields: {sorted(required - d.keys())}"
            )
        if not isinstance(d["c"], list):
            raise ValueError("macaroon caveats must be a list")
        return cls(
            identifier=str(d["id"]),
            payment_hash=str(d["ph"]),
            caveats=list(d["c"]),
            tag=str(d["t"]),
        )
