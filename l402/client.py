"""Client-side L402: parse challenges, pay, retry with the correct header.

Three pieces:

  parse_challenge_header(www_auth_value)  → ParsedChallenge
  make_auth_header(macaroon_token, preimage_hex) → "L402 <token>:<preimage>"
  L402Client(pay_callback)                — orchestrates the full dance

The full dance:
  1. GET / POST the protected URL
  2. If response is 402, parse WWW-Authenticate → ParsedChallenge
  3. Call pay_callback(parsed) → preimage_hex
  4. Retry the original request with Authorization header set
  5. Return the (now-200) response

`pay_callback` is YOUR integration point — the library deliberately
doesn't know how you pay invoices. Plug in:
  - Your wallet's API (LND sendpayment, Phoenixd payinvoice, …)
  - A human-in-the-loop prompt for desktop tools
  - A test stub that derives the preimage from a known seed
"""

from __future__ import annotations

import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable


class L402NetworkError(Exception):
    """Wraps transport-layer failures (DNS, connection refused, timeout,
    TLS handshake errors) so callers see one exception type for
    "couldn't talk to the server at all" instead of having to catch
    every urllib.error.URLError subclass."""


@dataclass(frozen=True)
class ParsedChallenge:
    """The fields a WWW-Authenticate L402 header carries."""
    macaroon_token: str
    invoice_bolt11: str


def parse_challenge_header(www_auth_value: str) -> ParsedChallenge:
    """Parse a `L402 macaroon="…", invoice="…"` header value.

    Tolerant of:
      - extra whitespace
      - parameter order (macaroon-then-invoice, or reverse)
      - missing trailing comma
      - quoted or unquoted values (RFC 7235 allows both)

    Raises ValueError if it can't find both macaroon and invoice.
    """
    if not www_auth_value or not www_auth_value.strip().lower().startswith("l402"):
        raise ValueError("not an L402 challenge")
    body = www_auth_value.strip()[len("L402"):].lstrip()

    def _extract(name: str) -> str | None:
        # Match name=value where value is either "quoted" or bareword.
        m = re.search(
            rf'(?:^|,)\s*{re.escape(name)}\s*=\s*(?:"([^"]*)"|([^,\s]+))',
            body, re.IGNORECASE,
        )
        if not m:
            return None
        return m.group(1) if m.group(1) is not None else m.group(2)

    macaroon = _extract("macaroon")
    invoice = _extract("invoice")
    if not macaroon or not invoice:
        raise ValueError(
            "L402 challenge missing macaroon and/or invoice parameter"
        )
    return ParsedChallenge(macaroon_token=macaroon, invoice_bolt11=invoice)


_PREIMAGE_HEX_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def make_auth_header(macaroon_token: str, preimage_hex: str) -> str:
    """Build the value for `Authorization: <return value>`.

    Validates both the macaroon token (no ':' which would corrupt the
    splitter on the server side) AND the preimage (must be exactly 64
    hex chars). Invalid preimages with whitespace or newlines would
    otherwise allow HTTP header-injection attacks via a compromised
    pay_callback.
    """
    if ":" in macaroon_token:
        raise ValueError(
            "macaroon token contains ':' which would corrupt the header"
        )
    if not _PREIMAGE_HEX_RE.match(preimage_hex):
        raise ValueError(
            "preimage_hex must be exactly 64 hex characters; refusing to "
            "build an Authorization header from input that could carry "
            "control characters or CRLF injection"
        )
    return f"L402 {macaroon_token}:{preimage_hex}"


PayCallback = Callable[[ParsedChallenge], str]


class L402Client:
    """High-level wrapper that handles the full L402 dance.

    Usage:
        def my_pay(challenge: ParsedChallenge) -> str:
            # decode challenge.invoice_bolt11, pay it via your wallet,
            # return the preimage hex
            return wallet.pay_and_get_preimage(challenge.invoice_bolt11)

        client = L402Client(pay_callback=my_pay)
        resp_status, resp_body = client.get("https://api.example.com/premium")

    No external HTTP dependency — uses urllib for portability. Returns
    (status_code, body_bytes) tuples. If you want richer ergonomics,
    use parse_challenge_header + make_auth_header directly with your
    own HTTP client (requests, httpx, aiohttp, anything).
    """

    def __init__(
        self,
        pay_callback: PayCallback,
        *,
        timeout_seconds: float = 30.0,
        max_retries: int = 1,
    ) -> None:
        self.pay_callback = pay_callback
        self.timeout = timeout_seconds
        self.max_retries = max_retries

    def request(
        self,
        method: str,
        url: str,
        *,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, bytes]:
        headers = dict(headers or {})
        # Up to max_retries+1 attempts: initial + retry-with-auth.
        for attempt in range(self.max_retries + 1):
            try:
                resp_status, resp_body, www_auth = self._one_call(
                    method, url, body, headers,
                )
            except urllib.error.HTTPError as e:
                # urllib raises HTTPError for non-2xx; we want 402 to be a
                # normal control flow, not an exception. _one_call already
                # catches it; re-raise anything that escapes.
                raise
            if resp_status != 402 or attempt == self.max_retries:
                return resp_status, resp_body
            if not www_auth:
                return resp_status, resp_body
            challenge = parse_challenge_header(www_auth)
            preimage_hex = self.pay_callback(challenge)
            headers["Authorization"] = make_auth_header(
                challenge.macaroon_token, preimage_hex,
            )
        return resp_status, resp_body

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> tuple[int, bytes]:
        return self.request("GET", url, headers=headers)

    def post(
        self, url: str, *, body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, bytes]:
        return self.request("POST", url, body=body, headers=headers)

    def _one_call(
        self, method: str, url: str,
        body: bytes | None, headers: dict[str, str],
    ) -> tuple[int, bytes, str | None]:
        req = urllib.request.Request(
            url, data=body, method=method, headers=dict(headers),
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status, resp.read(), resp.headers.get("WWW-Authenticate")
        except urllib.error.HTTPError as e:
            # 402 lives here. Pull headers + body off the response object.
            body_bytes = e.read() if hasattr(e, "read") else b""
            www_auth = e.headers.get("WWW-Authenticate") if e.headers else None
            return e.code, body_bytes, www_auth
        except urllib.error.URLError as e:
            # DNS failure, connection refused, timeout, TLS handshake fail —
            # surface as one library-defined exception so callers don't have
            # to know urllib's exception hierarchy.
            raise L402NetworkError(f"network error contacting {url}: {e}")
