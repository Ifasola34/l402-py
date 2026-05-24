"""l402 — Lightning paywall (LSAT/L402) for Python.

Server side:
  from l402 import make_challenge, authorize, DeterministicMockBackend
  chal = make_challenge(secret, ln, resource_id="premium:foo")
  ok = authorize(secret, ln, auth_header_value=h, resource_id="premium:foo")

Client side:
  from l402 import parse_challenge_header, make_auth_header, L402Client

Backends:
  from l402 import (
      DeterministicMockBackend, LndRestBackend,
      PhoenixdBackend, ClnRestBackend,
  )
"""

__version__ = "0.1.0"

from .backends import (
    ClnRestBackend,
    DeterministicMockBackend,
    LightningBackend,
    LndRestBackend,
    PhoenixdBackend,
)
from .client import (
    L402Client,
    L402NetworkError,
    ParsedChallenge,
    make_auth_header,
    parse_challenge_header,
)
from .macaroon import Macaroon
from .server import authorize, make_challenge
from .types import L402Challenge, LnInvoice

__all__ = [
    "__version__",
    "Macaroon",
    "LnInvoice", "L402Challenge",
    "make_challenge", "authorize",
    "parse_challenge_header", "make_auth_header", "L402Client",
    "ParsedChallenge", "L402NetworkError",
    "LightningBackend",
    "DeterministicMockBackend", "LndRestBackend", "PhoenixdBackend", "ClnRestBackend",
]
