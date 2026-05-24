"""l402 — command-line tool for paywall debugging and integration.

Subcommands:
  challenge            issue a fresh L402 challenge (mock backend)
  decode-challenge     parse a WWW-Authenticate header and pretty-print
  verify               check an Authorization header against a secret
  pay                  do the full L402 dance against a real URL using
                       the mock backend's "click to settle" demo flow

The first three are pure helpers — no network calls. `pay` is for
testing real L402-gated endpoints; you bring your own preimage source
(or use --reveal to drive the deterministic mock end-to-end if the
remote server happens to use it).
"""

from __future__ import annotations

import json
import secrets as pysecrets
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .backends import DeterministicMockBackend
from .client import L402Client, ParsedChallenge, parse_challenge_header
from .macaroon import Macaroon
from .server import authorize, make_challenge


console = Console()


def _load_secret(secret_arg: str | None) -> bytes:
    """Resolve a secret from the --secret flag (hex: prefix or passphrase).

    Falls back to a random 32-byte value with a warning — useful for
    the `challenge` subcommand where the secret is ephemeral demo data.
    """
    if secret_arg is None:
        secret = pysecrets.token_bytes(32)
        console.print(
            "[yellow]warning:[/yellow] no --secret given; using an "
            "ephemeral random secret (this run only)"
        )
        return secret
    if secret_arg.startswith("hex:"):
        try:
            decoded = bytes.fromhex(secret_arg[4:])
        except ValueError as e:
            raise click.ClickException(f"hex: secret malformed: {e}")
        if len(decoded) < 16:
            raise click.ClickException(
                "secret too short; need ≥16 bytes (32+ recommended)"
            )
        return decoded
    if len(secret_arg.encode("utf-8")) < 16:
        raise click.ClickException(
            "passphrase too short; use ≥16 bytes or 'hex:' + 32 random bytes"
        )
    return secret_arg.encode("utf-8")


@click.group()
def cli() -> None:
    """l402 — Lightning paywall debugging CLI."""


@cli.command()
@click.option("--resource", required=True, help="Resource identifier the macaroon will be scoped to.")
@click.option("--amount-msat", type=int, default=100, show_default=True)
@click.option("--secret", default=None, help="hex:<hex> or a ≥16-byte passphrase. Random if omitted.")
@click.option("--expiry-seconds", type=int, default=3600, show_default=True)
def challenge(resource: str, amount_msat: int, secret: str | None, expiry_seconds: int) -> None:
    """Issue a fresh L402 challenge using the in-process mock backend.

    Useful for showing colleagues what a 402 looks like, for testing
    clients without spinning up a real LN node, and for generating
    fixtures.
    """
    secret_b = _load_secret(secret)
    ln = DeterministicMockBackend()
    chal = make_challenge(
        secret_b, ln, resource_id=resource,
        amount_msat=amount_msat, expiry_seconds=expiry_seconds,
    )
    t = Table(title="L402 challenge", show_header=False)
    t.add_row("resource",       resource)
    t.add_row("amount_msat",    str(amount_msat))
    t.add_row("payment_hash",   chal.payment_hash)
    t.add_row("macaroon_token", chal.macaroon_token[:48] + "…" + chal.macaroon_token[-16:])
    t.add_row("invoice (mock)", chal.invoice_bolt11)
    console.print(t)
    console.print(Panel(chal.header_value(), title="WWW-Authenticate header value"))
    preimage_hex = ln.reveal_preimage(chal.payment_hash)
    console.print(Panel(
        f"L402 {chal.macaroon_token}:{preimage_hex}",
        title="Sample Authorization header (mock backend reveal)",
    ))


@cli.command("decode-challenge")
@click.argument("header_value", required=True)
def decode_challenge(header_value: str) -> None:
    """Parse a `WWW-Authenticate: L402 ...` header and pretty-print.

    Pass JUST the header VALUE (everything after `WWW-Authenticate:`),
    quoted. Useful when staring at a raw 402 from curl/httpie.
    """
    try:
        parsed = parse_challenge_header(header_value)
    except ValueError as e:
        raise click.ClickException(str(e))
    t = Table(title="parsed L402 challenge", show_header=False)
    t.add_row("macaroon_token", parsed.macaroon_token[:48] + "…" + parsed.macaroon_token[-16:])
    t.add_row("invoice_bolt11", parsed.invoice_bolt11)
    console.print(t)
    try:
        m = Macaroon.from_token(parsed.macaroon_token)
    except ValueError as e:
        console.print(f"[yellow]could not decode macaroon body:[/yellow] {e}")
        return
    t = Table(title="macaroon body", show_header=False)
    t.add_row("identifier",   m.identifier)
    t.add_row("payment_hash", m.payment_hash)
    t.add_row("caveats",      json.dumps(m.caveats))
    t.add_row("tag (b64)",    m.tag[:20] + "…")
    console.print(t)


@cli.command()
@click.option("--auth-header", required=True, help="Value of Authorization: <here>")
@click.option("--resource", required=True)
@click.option("--secret", required=True, help="hex:<hex> or ≥16-byte passphrase")
@click.option("--require-backend-settled", is_flag=True,
              help="Also require backend confirmation (uses an empty mock backend that says everything is paid).")
def verify(auth_header: str, resource: str, secret: str, require_backend_settled: bool) -> None:
    """Check a real `Authorization: L402 ...` header against a known secret.

    For the require-backend-settled mode this uses a stub that always
    says 'paid' — the point is exercising the code path, not actually
    asking your node.
    """
    secret_b = _load_secret(secret)

    class _AlwaysPaid:
        name = "stub"
        def create_invoice(self, *_a, **_k): raise NotImplementedError
        def check_paid(self, *_a, **_k): return True

    ok = authorize(
        secret_b, _AlwaysPaid(),
        auth_header_value=auth_header, resource_id=resource,
        require_backend_settled=require_backend_settled,
    )
    if ok:
        console.print(Panel.fit("[bold green]AUTHORIZED[/bold green]", border_style="green"))
        sys.exit(0)
    else:
        console.print(Panel.fit("[bold red]REJECTED[/bold red]", border_style="red"))
        sys.exit(1)


@cli.command()
@click.argument("url")
@click.option("--method", default="GET", show_default=True)
@click.option("--preimage-from", type=click.Path(exists=True), default=None,
              help="Read the preimage hex from a file when 402 arrives. "
                   "Lets you pay externally then resume here.")
def pay(url: str, method: str, preimage_from: str | None) -> None:
    """Hit a URL, handle 402 by reading a preimage from a file, retry.

    Real production paying happens in your wallet/node, not in a CLI.
    This subcommand exists for end-to-end manual tests against a
    deployed L402 endpoint.
    """
    def _pay_cb(challenge: ParsedChallenge) -> str:
        console.print(Panel(
            f"invoice: {challenge.invoice_bolt11}",
            title="server demands payment", border_style="yellow",
        ))
        if preimage_from:
            return Path(preimage_from).read_text().strip()
        return click.prompt("preimage hex (from your wallet)", type=str).strip()

    client = L402Client(pay_callback=_pay_cb)
    status, body = client.request(method, url)
    console.print(Panel.fit(
        f"final status: {status}\n{len(body)} bytes body",
        border_style="green" if status < 400 else "red",
    ))
    try:
        sys.stdout.buffer.write(body)
    except Exception:
        sys.stdout.write(body.decode("utf-8", errors="replace"))


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
