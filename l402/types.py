"""Shared value types used by both server and client sides of L402."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class LnInvoice:
    """A Lightning invoice issued by a backend."""

    bolt11: str
    payment_hash: str    # 32-byte hex
    amount_msat: int


@dataclass(frozen=True)
class L402Challenge:
    """The bundle of artifacts a server hands to an unauthenticated client.

    The challenge becomes a `WWW-Authenticate: L402 macaroon="…", invoice="…"`
    header (see header_value()), plus the payment_hash is surfaced for
    convenience so clients don't have to re-derive it from the invoice.
    """

    macaroon_token: str
    invoice_bolt11: str
    payment_hash: str

    def header_value(self) -> str:
        return (
            f'L402 macaroon="{self.macaroon_token}", '
            f'invoice="{self.invoice_bolt11}"'
        )
