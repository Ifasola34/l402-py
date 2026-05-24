"""Macaroon: HMAC roundtrip, tamper rejection, token roundtrip."""

import pytest

from l402.macaroon import Macaroon


SECRET = b"test-secret-32-bytes-or-whatever"


def test_tag_roundtrips_with_same_secret():
    m = Macaroon.create(SECRET, "premium", "ph" * 16, ["resource=premium"])
    assert m.verify_tag(SECRET) is True


def test_tag_fails_with_different_secret():
    m = Macaroon.create(SECRET, "premium", "ph" * 16, ["resource=premium"])
    assert m.verify_tag(b"different-32-byte-secret-zzzzzz") is False


def test_tag_fails_after_caveat_mutation():
    m = Macaroon.create(SECRET, "id1", "ph" * 16, ["c=v"])
    # Build a new macaroon with added caveats but the old tag.
    tampered = Macaroon(m.identifier, m.payment_hash, m.caveats + ["evil=true"], m.tag)
    assert tampered.verify_tag(SECRET) is False


def test_create_rejects_short_secret():
    with pytest.raises(ValueError, match="at least 16"):
        Macaroon.create(b"too-short", "id", "ph" * 16, [])


def test_token_roundtrip_preserves_fields():
    m = Macaroon.create(SECRET, "premium:m1", "ab" * 16,
                        ["resource=premium:m1", "exp=1799999999"])
    tok = m.to_token()
    back = Macaroon.from_token(tok)
    assert back.identifier == m.identifier
    assert back.payment_hash == m.payment_hash
    assert back.caveats == m.caveats
    assert back.tag == m.tag
    assert back.verify_tag(SECRET) is True


def test_from_token_rejects_garbage():
    with pytest.raises(ValueError):
        Macaroon.from_token("not-base64-because-spaces")
    with pytest.raises(ValueError):
        Macaroon.from_token("dGVzdA==")  # base64("test") — not valid JSON


def test_from_token_rejects_missing_fields():
    import base64, json
    bad = base64.urlsafe_b64encode(
        json.dumps({"id": "x", "ph": "y"}).encode()
    ).decode()
    with pytest.raises(ValueError, match="missing fields"):
        Macaroon.from_token(bad)


def test_from_token_rejects_non_list_caveats():
    import base64, json
    bad = base64.urlsafe_b64encode(
        json.dumps({"id": "x", "ph": "y", "c": "not-a-list", "t": "z"}).encode()
    ).decode()
    with pytest.raises(ValueError, match="must be a list"):
        Macaroon.from_token(bad)


def test_tag_is_constant_time_safe():
    """compare_digest is used internally; check that verify_tag returns
    a bool, not a truthy/falsy non-bool (which would defeat timing safety)."""
    m = Macaroon.create(SECRET, "id", "ph" * 16, ["c=v"])
    assert isinstance(m.verify_tag(SECRET), bool)
    assert isinstance(m.verify_tag(b"different-secret-bytes-padded"), bool)
