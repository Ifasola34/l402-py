"""CLI: challenge / decode-challenge / verify."""

import json
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from l402.backends import DeterministicMockBackend
from l402.cli import cli
from l402.macaroon import Macaroon
from l402.server import make_challenge


SECRET_HEX = "hex:" + ("ab" * 32)
SECRET_BYTES = bytes.fromhex("ab" * 32)


def test_challenge_runs_and_prints_header_value():
    runner = CliRunner()
    r = runner.invoke(cli, [
        "challenge",
        "--resource", "premium:m1",
        "--secret", SECRET_HEX,
        "--amount-msat", "500",
    ])
    assert r.exit_code == 0, r.output
    assert "WWW-Authenticate" in r.output
    assert "L402" in r.output
    assert "premium:m1" in r.output


def test_challenge_warns_when_secret_omitted():
    runner = CliRunner()
    r = runner.invoke(cli, ["challenge", "--resource", "r1"])
    assert r.exit_code == 0
    assert "warning" in r.output.lower()
    assert "ephemeral" in r.output.lower()


def test_decode_challenge_pretty_prints_macaroon_body():
    ln = DeterministicMockBackend()
    chal = make_challenge(SECRET_BYTES, ln, resource_id="r1")
    runner = CliRunner()
    r = runner.invoke(cli, ["decode-challenge", chal.header_value()])
    assert r.exit_code == 0
    assert "macaroon_token" in r.output
    assert "invoice_bolt11" in r.output
    assert "identifier" in r.output
    assert "r1" in r.output


def test_decode_challenge_errors_on_non_l402():
    runner = CliRunner()
    r = runner.invoke(cli, ["decode-challenge", "Bearer abcdef"])
    assert r.exit_code != 0
    assert "not an L402" in r.output


def test_verify_authorizes_a_real_header():
    ln = DeterministicMockBackend()
    chal = make_challenge(SECRET_BYTES, ln, resource_id="r1")
    preimage = ln.reveal_preimage(chal.payment_hash)
    auth = f"L402 {chal.macaroon_token}:{preimage}"
    runner = CliRunner()
    r = runner.invoke(cli, [
        "verify",
        "--auth-header", auth,
        "--resource", "r1",
        "--secret", SECRET_HEX,
    ])
    assert r.exit_code == 0
    assert "AUTHORIZED" in r.output


def test_verify_rejects_wrong_secret():
    ln = DeterministicMockBackend()
    chal = make_challenge(SECRET_BYTES, ln, resource_id="r1")
    preimage = ln.reveal_preimage(chal.payment_hash)
    auth = f"L402 {chal.macaroon_token}:{preimage}"
    other = "hex:" + ("cd" * 32)
    runner = CliRunner()
    r = runner.invoke(cli, [
        "verify",
        "--auth-header", auth,
        "--resource", "r1",
        "--secret", other,
    ])
    assert r.exit_code == 1
    assert "REJECTED" in r.output


def test_verify_rejects_short_passphrase_secret():
    runner = CliRunner()
    r = runner.invoke(cli, [
        "verify",
        "--auth-header", "L402 x:y",
        "--resource", "r",
        "--secret", "short",
    ])
    assert r.exit_code != 0
    assert "too short" in r.output.lower()
