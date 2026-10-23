"""The trust checks, below the level of the vectors: helpers, boundaries and the branches a vector does not reach."""

import json
from datetime import UTC, datetime

import pytest

from chokr_spec import data_dir, interop, trust
from chokr_spec.keys import jwk_alg, normalize_alg, thumbprint, thumbprint_input, verify_raw
from chokr_spec.signatures import Rejected, b64url_encode

SCHEMAS = data_dir() / "schemas"
NOW = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
ED = {"kty": "OKP", "crv": "Ed25519", "x": "A" * 43}


def code_of(call, *args, **kwargs) -> str:
    with pytest.raises(Rejected) as caught:
        call(*args, **kwargs)
    return caught.value.code


# ---- keys ------------------------------------------------------------------------------------------------------------


def test_algorithm_names_are_the_closed_list():
    assert normalize_alg("EdDSA") == normalize_alg("Ed25519") == "Ed25519"
    assert [normalize_alg(n) for n in ("none", "HS256", "eddsa", None, 5)] == [None] * 5
    assert jwk_alg({"kty": "RSA"}) == "RS256" and jwk_alg({"kty": "EC", "crv": "P-256"}) == "ES256"
    assert jwk_alg({"kty": "EC", "crv": "P-384"}) is None and jwk_alg({"kty": "OKP", "alg": "none"}) is None


def test_a_thumbprint_needs_a_public_key_of_a_known_type():
    for jwk in ({"kty": "oct", "k": "x"}, {"kty": "OKP", "crv": "Ed25519"}, {"kty": "RSA", "n": "x"}):
        with pytest.raises(ValueError, match="not a public key"):
            thumbprint_input(jwk)
    assert thumbprint(ED) == thumbprint({**ED, "kid": "another", "use": "sig"})


def test_a_key_of_the_wrong_kind_or_curve_is_unsupported_not_invalid():
    for jwk in (
        {"kty": "EC", "crv": "P-384", "alg": "ES256", "x": "AA", "y": "AA"},
        {"kty": "OKP", "crv": "Ed25519", "alg": "ES256", "x": "AA"},
        {"kty": "oct"},
    ):
        assert code_of(verify_raw, jwk, b"m", b"s") == "UNSUPPORTED_ALGORITHM"


def test_a_malformed_key_member_is_an_invalid_signature():
    assert code_of(verify_raw, {**ED, "x": "!!"}, b"m", b"s" * 64) == "SIGNATURE_INVALID"
    assert code_of(verify_raw, {"kty": "OKP", "crv": "Ed25519"}, b"m", b"s" * 64) == "SIGNATURE_INVALID"


# ---- time and configuration ------------------------------------------------------------------------------------------


@pytest.mark.parametrize("skew", [True, -1, 301, 1.5, "30", None])
def test_a_clock_tolerance_outside_zero_to_300_is_refused(skew):
    assert code_of(trust.check_skew, skew) == "SCHEMA_INVALID"


def test_the_clock_tolerance_limits_are_accepted():
    assert trust.check_skew(0) == 0 and trust.check_skew(300) == 300


@pytest.mark.parametrize(
    "text", ["2026-06-01T12:00:00+00:00", "2026-06-01 12:00:00Z", "2026-06-01T12:00:00", 20260601, None]
)
def test_only_utc_timestamps_with_z_are_times(text):
    assert code_of(trust.parse_time, text) == "SCHEMA_INVALID"


def test_the_window_is_half_open_on_the_tolerance():
    issued, expires = trust.parse_time("2026-06-01T12:00:30Z"), trust.parse_time("2026-06-01T11:59:30Z")
    trust.check_window(issued, None, NOW, 30)  # now equals issued - tolerance
    assert code_of(trust.check_window, issued, None, NOW, 29) == "CREDENTIAL_NOT_YET_VALID"
    assert (
        code_of(trust.check_window, trust.parse_time("2026-05-01T00:00:00Z"), expires, NOW, 30) == "CREDENTIAL_EXPIRED"
    )
    trust.check_window(trust.parse_time("2026-05-01T00:00:00Z"), expires, NOW, 31)


# ---- trust store -----------------------------------------------------------------------------------------------------


def test_a_query_for_every_type_is_matched_only_by_a_wildcard_relationship():
    store = trust.TrustStore(
        relationships=[
            {"issuer": "a", "evidence_type": "*"},
            {"issuer": "b", "evidence_type": "COMPLIANCE"},
            {"issuer": "c"},
        ]
    )
    assert store.trusted("a", "COMPLIANCE") and store.trusted("a") and store.trusted("c")
    assert store.trusted("b", "COMPLIANCE") and store.trusted("b") is None and store.trusted("b", "OWNERSHIP") is None
    assert store.trusted("nobody") is None


def test_an_unknown_id_is_active_and_suspended_is_not():
    store = trust.TrustStore(status={"x": "SUSPENDED", "y": "REVOKED", "z": "ACTIVE"})
    assert store.active("z", "unknown") and not store.active("x") and not store.active("z", "y")


def test_a_store_needs_a_valid_trust_config():
    assert code_of(trust.TrustStore.load, {"schema_version": "1.0", "issuer_keys": []}, SCHEMAS) == "SCHEMA_INVALID"


# ---- subjects and attenuation ----------------------------------------------------------------------------------------


def test_authority_for_a_subject():
    assert trust.authority_for_subject("urn:chokr:org:acme:agent:buyer") == "org:acme"
    assert trust.authority_for_subject("spiffe://td/agent") == "spiffe://td/agent"
    assert trust.authority_for_subject("did:web:example.com") == "did:web:example.com"
    for bad in ("urn:chokr:org:acme", "urn:chokr:org:a:b:agent:c", "urn:chokr:org::agent:x"):
        assert code_of(trust.authority_for_subject, bad) == "SCHEMA_INVALID"


@pytest.mark.parametrize(
    ("op", "parent", "child", "narrower"),
    [
        ("lte", 10, 10, True),
        ("lte", 10, 11, False),
        ("lt", 10, 9, True),
        ("lt", 10, 10.5, False),
        ("gte", 10, 10, True),
        ("gte", 10, 9, False),
        ("gt", 10, 11, True),
        ("gt", 10, 9, False),
        ("lte", 10, True, False),
        ("lte", "10", 5, False),
        ("gte", 10, None, False),
        ("in", [1, 2], [1], True),
        ("in", [1, 2], [1, 3], False),
        ("in", [1], "x", False),
        ("in", "x", [1], False),
        ("nin", [1], [1, 2], True),
        ("nin", [1, 2], [1], False),
        ("eq", {"a": 1, "b": 2}, {"b": 2, "a": 1}, True),
        ("eq", 1, 2, False),
        ("starts_with", "ab", "ab", True),
        ("regex", "^a", "^b", False),
    ],
)
def test_a_constraint_value_is_narrower_only_under_the_same_operator(op, parent, child, narrower):
    assert trust._narrower(op, parent, child) is narrower


def test_a_grant_is_covered_by_one_of_several_parents():
    wide = {"action": "a:b", "resource_type": "r", "constraints": [{"path": "purpose", "op": "eq", "value": "x"}]}
    other = {"action": "a:b", "resource_type": "r", "constraints": [{"path": "purpose", "op": "eq", "value": "y"}]}
    trust.check_covered([wide, other], [other])
    assert code_of(trust.check_covered, [wide], [other]) == "CONSTRAINT_VIOLATED"
    assert code_of(trust.check_covered, [wide], [{"action": "a:c", "resource_type": "r"}]) == "DELEGATION_ESCALATION"
    trust.check_covered(
        [{"action": "a:b", "resource_type": "r"}], [wide]
    )  # an unconstrained parent: any constraint narrows


def test_a_link_with_an_embedded_key_that_does_not_match_its_delegator_is_not_self_certifying():
    link = {
        "issuer": "urn:chokr:key:sha256:" + "0" * 64,
        "delegator": "urn:chokr:key:sha256:" + "0" * 64,
        "keys": [{"kty": "OKP", "kid": "k", "crv": "Ed25519", "x": "A" * 43}],
        "signature": {"alg": "Ed25519", "kid": "k", "value": "A" * 86},
    }
    assert trust._self_certifying(link) is None
    broken = {**link, "keys": [{"kty": "oct", "kid": "k"}]}
    assert trust._self_certifying(broken) is None


def test_a_proof_whose_key_is_not_embedded_stops_a_self_verifying_link():
    store = trust.TrustStore()
    document = {"proofs": [{"alg": "Ed25519", "kid": "missing", "value": "A" * 86}] * 2}
    assert code_of(trust.verify_signed, document, store, "x", embedded={}) == "KEY_NOT_FOUND"


def test_a_document_with_no_signature_member_is_refused_before_any_key_is_used():
    assert code_of(trust.verify_signed, {"id": "x"}, trust.TrustStore(), "x") == "SCHEMA_INVALID"


# ---- credential epoch ------------------------------------------------------------------------------------------------


def test_a_credential_epoch_against_the_mark():
    assert trust.check_credential_epoch(3, 3, "reject") == {"status": "current"}
    assert trust.check_credential_epoch(4, 3, "reject") == {"status": "unconfirmed"}
    assert trust.check_credential_epoch(None, 0, "reject") == {"status": "current"}
    assert trust.check_credential_epoch(1, 3, "allow_with_signal") == {"status": "stale"}
    assert code_of(trust.check_credential_epoch, 1, 3, "reject") == "AUTHORITY_EPOCH_STALE"


# ---- interop ---------------------------------------------------------------------------------------------------------


def test_base58_round_trips_with_leading_zero_bytes():
    for data in (b"", b"\x00", b"\x00\x00ab", b"hello", bytes(range(40))):
        assert interop.base58_decode(interop.base58_encode(data)) == data
    assert interop.base58_encode(b"\x00\x00\x01") == "112"
    for bad in ("0", "O", "I", "l", "a b"):
        with pytest.raises(ValueError):
            interop.base58_decode(bad)


def test_a_secret_key_must_carry_the_ed25519_prefix():
    document = {"proof": {"type": "DataIntegrityProof"}}
    with pytest.raises(ValueError, match="Ed25519"):
        interop.sign_integrity_eddsa(document, "z" + interop.base58_encode(b"\x01\x02" + b"\x00" * 32))
    with pytest.raises(ValueError, match="Ed25519"):
        interop.sign_integrity_eddsa(document, "z" + interop.base58_encode(b"\x80\x26" + b"\x00" * 31))


def segment(value: bytes) -> str:
    return b64url_encode(value)


@pytest.mark.parametrize("header", [b"not json", b"[1]", b'"text"', b"\xff\xfe"])
def test_a_jws_header_that_is_not_a_json_object_is_refused(header):
    token = f"{segment(header)}.{segment(b'{}')}.{segment(b'sig')}"
    assert code_of(interop.verify_compact, token, [ED], now=0) == "SCHEMA_INVALID"


def test_a_jws_payload_that_is_not_a_json_object_is_refused():
    token = f"{segment(b'{}')}.{segment(b'[]')}.{segment(b'sig')}"
    assert code_of(interop.verify_compact, token, [ED], now=0) == "SCHEMA_INVALID"


def test_a_presentation_without_a_tilde_is_refused():
    jwt = f"{segment(b'{}')}.{segment(b'{}')}.{segment(b'sig')}"
    assert code_of(interop.verify_sd_jwt, jwt, [ED], now=0) == "SCHEMA_INVALID"


def test_the_integrity_hashes_use_the_document_context_only_when_it_has_one():
    proof = {"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022"}
    without = interop.integrity_hashes({"a": 1, "proof": proof})
    with_context = interop.integrity_hashes({"@context": ["x"], "a": 1, "proof": proof})
    assert without["proof_config_hash"] != with_context["proof_config_hash"]
    assert without["document_hash"] == interop.integrity_hashes({"a": 1, "proof": {"other": 1}})["document_hash"]


# ---- the data --------------------------------------------------------------------------------------------------------


PRIVATE_MEMBERS = {"d", "p", "q", "dp", "dq", "qi", "priv", "k"}


def keys_in(value, found):
    if isinstance(value, dict):
        if value.get("kty") is not None:
            found.append(value)
        for item in value.values():
            keys_in(item, found)
    elif isinstance(value, list):
        for item in value:
            keys_in(item, found)


def test_no_vector_publishes_a_private_key_member():
    found: list[dict] = []
    vectors = sorted((data_dir() / "vectors" / "trust").rglob("*.json"))
    assert vectors
    for path in vectors:
        keys_in(json.loads(path.read_text("utf-8")), found)
    assert len(found) > 100
    leaked = [k for k in found if PRIVATE_MEMBERS & set(k)]
    # the schema vectors that prove a private member is refused live under core; trust vectors never carry one
    assert leaked == []


def test_every_trust_vector_states_why_it_exists():
    for path in sorted((data_dir() / "vectors" / "trust").rglob("*.json")):
        vector = json.loads(path.read_text("utf-8"))
        assert vector["description"].strip() and vector["class"] in {"valid", "invalid", "tamper"}, path.name


def test_the_trust_schema_vectors_agree_with_the_verifiers_on_the_private_member_rule():
    path = data_dir() / "vectors" / "core" / "schema" / "trust_config_issuer_key_with_a_private_member.json"
    assert json.loads(path.read_text("utf-8"))["expected"] == {"valid": False}
