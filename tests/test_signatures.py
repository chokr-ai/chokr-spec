import copy

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from chokr_spec.canonical import canonicalize
from chokr_spec.signatures import Rejected, b64url_decode, b64url_encode, verify_document


def make_key(kid: str = "k1") -> tuple[Ed25519PrivateKey, dict]:
    private = Ed25519PrivateKey.generate()
    raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return private, {"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "kid": kid, "x": b64url_encode(raw)}


def sign(private: Ed25519PrivateKey, document: dict, kid: str = "k1", alg: str = "EdDSA") -> dict:
    body = {k: v for k, v in document.items() if k != "signature"}
    value = b64url_encode(private.sign(canonicalize(body)))
    return {**body, "signature": {"alg": alg, "kid": kid, "value": value}}


@pytest.fixture
def signed() -> tuple[dict, dict]:
    private, jwk = make_key()
    return sign(private, {"outcome": "allow", "n": 1}), {"k1": jwk}


def code_of(document: dict, keys: dict, allowed=None) -> str:
    with pytest.raises(Rejected) as caught:
        verify_document(document, keys, allowed)
    return caught.value.code


def test_a_valid_signature_is_accepted(signed):
    document, keys = signed
    verify_document(document, keys, None)
    verify_document(document, keys, {"k1"})


def test_the_order_of_keys_does_not_matter(signed):
    document, keys = signed
    verify_document(dict(reversed(document.items())), keys, None)


def test_a_missing_signature(signed):
    document, keys = signed
    unsigned = {k: v for k, v in document.items() if k != "signature"}
    assert code_of(unsigned, keys) == "VERDICT_UNSIGNED"
    verify_document(unsigned, keys, None, require_signature=False)


@pytest.mark.parametrize("signature", ["text", {"alg": "EdDSA", "kid": "k1"}, {"alg": 1, "kid": "k1", "value": "x"}])
def test_a_malformed_signature(signed, signature):
    document, keys = signed
    assert code_of({**document, "signature": signature}, keys) == "SIGNATURE_INVALID"


def test_a_changed_document_is_rejected(signed):
    document, keys = signed
    assert code_of({**document, "outcome": "deny"}, keys) == "SIGNATURE_INVALID"
    assert code_of({**document, "extra": 1}, keys) == "SIGNATURE_INVALID"


def test_the_wrong_key_for_a_kid_is_rejected(signed):
    document, _ = signed
    _, other = make_key()
    assert code_of(document, {"k1": other}) == "SIGNATURE_INVALID"


def test_the_kid_rules(signed):
    document, keys = signed
    assert code_of(document, keys, allowed={"k2"}) == "KID_NOT_ALLOWED"
    assert code_of(document, {}) == "UNKNOWN_KID"


def test_the_algorithm_of_the_key_is_the_only_one_used(signed):
    document, keys = signed
    for alg in ("none", "None", "HS256"):
        tampered = copy.deepcopy(document)
        tampered["signature"]["alg"] = alg
        assert code_of(tampered, keys) == "SIGNATURE_INVALID"
    ed25519_name = copy.deepcopy(document)
    ed25519_name["signature"]["alg"] = "Ed25519"
    verify_document(ed25519_name, keys, None)


def test_a_key_that_names_no_usable_algorithm(signed):
    document, keys = signed
    no_alg = {"k1": {"kty": "OKP", "crv": "Ed25519", "x": keys["k1"]["x"]}}
    verify_document(document, no_alg, None)
    assert code_of(document, {"k1": {"kty": "RSA", "n": "x", "e": "AQAB"}}) == "SIGNATURE_INVALID"
    assert code_of(document, {"k1": {"kty": "RSA", "alg": "RS256", "n": "x", "e": "AQAB"}}) == "UNSUPPORTED_ALGORITHM"
    assert code_of(document, {"k1": {**keys["k1"], "crv": "P-256"}}) == "UNSUPPORTED_ALGORITHM"


def test_a_signature_that_is_not_base64url(signed):
    document, keys = signed
    broken = copy.deepcopy(document)
    broken["signature"]["value"] = "***"
    assert code_of(broken, keys) == "SIGNATURE_INVALID"
    broken["signature"]["value"] = "caf\u00e9"
    assert code_of(broken, keys) == "SIGNATURE_INVALID"


def test_a_value_that_cannot_be_canonicalised_is_rejected(signed):
    _, keys = signed
    document = {"n": float("nan"), "signature": {"alg": "EdDSA", "kid": "k1", "value": "AAAA"}}
    assert code_of(document, keys) == "SIGNATURE_INVALID"


def test_base64url_round_trip():
    data = bytes(range(256))
    assert b64url_decode(b64url_encode(data)) == data
    with pytest.raises(ValueError):
        b64url_decode(5)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        b64url_decode("A")


@pytest.mark.parametrize(
    "text",
    ["YW Jj", "YW\nJj", "YWJj==", "YWJj=", "ab+/", "YWJjZ", " YWJj", "YWJj\n", "YR"],
)
def test_base64url_is_strict(text):
    with pytest.raises(ValueError):
        b64url_decode(text)


def test_the_text_a_lenient_decoder_would_accept_is_refused_in_a_signature(signed):
    import base64

    document, keys = signed
    value = document["signature"]["value"]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    loose = value[:-1] + alphabet[alphabet.index(value[-1]) | 1]

    def lenient(text: str) -> bytes:
        cleaned = text.replace("\n", "").replace("=", "")
        return base64.urlsafe_b64decode(cleaned + "=" * (-len(cleaned) % 4))

    for variant in (value[:4] + "\n" + value[4:], value + "==", loose):
        assert lenient(variant) == lenient(value)
        tampered = copy.deepcopy(document)
        tampered["signature"]["value"] = variant
        assert code_of(tampered, keys) == "SIGNATURE_INVALID"


def test_a_kid_outside_the_allowed_set_is_reported_before_the_key_lookup(signed):
    document, keys = signed
    unknown = copy.deepcopy(document)
    unknown["signature"]["kid"] = "k9"
    assert code_of(unknown, keys) == "UNKNOWN_KID"
    assert code_of(unknown, keys, allowed={"k2"}) == "KID_NOT_ALLOWED"
