"""Write the `trust` conformance vectors: keys, credentials, delegations, evidence, passports, proofs of possession,
epochs, key bindings, compact JWS, W3C Data Integrity proofs and SD-JWT.

Every key is derived from its name, so a run is reproducible: Ed25519, P-256 (deterministic ECDSA) and RSA give the same
bytes every time. ML-DSA signs with fresh randomness, so the ML-DSA vectors change on each run; the committed files are
the reference and `--check` leaves them alone. The test keys protect nothing.

Documents are signed here with `cryptography` and `rfc8785` only. Each vector states the result a verifier must reach,
and the run stops if the reference checker disagrees, so a vector never records what the checker merely happens to do.

Run `python tools/gen_trust_vectors.py` to rewrite the vectors, or `--check` to compare a fresh run with the committed
ones (all but the ML-DSA vectors).
"""

import base64
import copy
import hashlib
import json
import pathlib
import sys
from dataclasses import dataclass
from typing import Any

import rfc8785
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, mldsa, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from chokr_spec import data_dir, interop
from chokr_spec.executors import COMPUTE, Context
from chokr_spec.runner import _subset

ROOT = pathlib.Path(__file__).resolve().parents[1] / "vectors" / "trust"
NOW = "2026-06-01T12:00:00Z"
NOW_EPOCH = 1780315200  # NOW as seconds since the epoch
ISSUED, EXPIRES = "2026-05-01T00:00:00Z", "2026-07-01T00:00:00Z"
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def jcs(value: Any) -> bytes:
    return rfc8785.dumps(value)


def seed(name: str, size: int = 32) -> bytes:
    out, counter = b"", 0
    while len(out) < size:
        out += hashlib.sha256(f"chokr-spec test key|{name}|{counter}".encode()).digest()
        counter += 1
    return out[:size]


# ---- deterministic test keys ---------------------------------------------------------------------------------------


def _is_prime(n: int) -> bool:
    if n < 2:
        return False
    small = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for p in small:
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d, r = d // 2, r + 1
    for a in small:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(name: str, bits: int) -> int:
    counter = 0
    while True:
        raw = int.from_bytes(seed(f"{name}|{counter}", bits // 8), "big")
        candidate = raw | (3 << (bits - 2)) | 1  # top two bits set, so p*q has the full length
        if _is_prime(candidate) and (candidate - 1) % 65537 != 0:
            return candidate
        counter += 1


def rsa_key(name: str, bits: int) -> rsa.RSAPrivateKey:
    p, q = _prime(f"{name}|p", bits // 2), _prime(f"{name}|q", bits // 2)
    d = pow(65537, -1, (p - 1) * (q - 1))
    numbers = rsa.RSAPrivateNumbers(
        p, q, d, d % (p - 1), d % (q - 1), pow(q, -1, p), rsa.RSAPublicNumbers(65537, p * q)
    )
    return numbers.private_key()


@dataclass
class Key:
    kid: str
    alg: str
    private: Any
    jwk: dict[str, Any]

    def sign(self, message: bytes) -> bytes:
        if self.alg == "Ed25519":
            return bytes(self.private.sign(message))
        if self.alg == "ES256":
            der = self.private.sign(message, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
            r, s = decode_dss_signature(der)
            return r.to_bytes(32, "big") + s.to_bytes(32, "big")
        if self.alg == "RS256":
            return bytes(self.private.sign(message, padding.PKCS1v15(), hashes.SHA256()))
        return bytes(self.private.sign(message))

    def signature(self, message: bytes, *, kid: str | None = None, alg: str | None = None) -> dict[str, str]:
        return {"alg": alg or self.alg, "kid": kid or self.kid, "value": b64u(self.sign(message))}


def ed25519_key(kid: str) -> Key:
    private = ed25519.Ed25519PrivateKey.from_private_bytes(seed(kid))
    x = private.public_key().public_bytes_raw()
    return Key(kid, "Ed25519", private, {"kty": "OKP", "crv": "Ed25519", "kid": kid, "alg": "Ed25519", "x": b64u(x)})


def p256_key(kid: str) -> Key:
    value = int.from_bytes(seed(kid), "big") % (P256_ORDER - 1) + 1
    private = ec.derive_private_key(value, ec.SECP256R1())
    n = private.public_key().public_numbers()
    jwk = {"kty": "EC", "crv": "P-256", "kid": kid, "alg": "ES256"}
    return Key(kid, "ES256", private, {**jwk, "x": b64u(n.x.to_bytes(32, "big")), "y": b64u(n.y.to_bytes(32, "big"))})


def rsa_signing_key(kid: str, bits: int = 2048) -> Key:
    private = rsa_key(kid, bits)
    n = private.public_key().public_numbers()
    jwk = {"kty": "RSA", "kid": kid, "alg": "RS256", "n": b64u(n.n.to_bytes(bits // 8, "big")), "e": "AQAB"}
    return Key(kid, "RS256", private, jwk)


def mldsa_key(kid: str, level: str = "44") -> Key:
    cls = {"44": mldsa.MLDSA44PrivateKey, "65": mldsa.MLDSA65PrivateKey, "87": mldsa.MLDSA87PrivateKey}[level]
    private = cls.from_seed_bytes(seed(kid))
    alg = f"ML-DSA-{level}"
    return Key(
        kid, alg, private, {"kty": "AKP", "kid": kid, "alg": alg, "pub": b64u(private.public_key().public_bytes_raw())}
    )


KEYS = {
    "acme": ed25519_key("acme-1"),
    "acme_p256": p256_key("acme-p256"),
    "acme_pq": mldsa_key("acme-pq"),
    "acme_rsa": rsa_signing_key("acme-rsa"),
    "auditor": ed25519_key("auditor-1"),
    "other": ed25519_key("other-1"),
    "agent": ed25519_key("agent-1"),
    "mallory": ed25519_key("mallory-1"),
}
BUYER = "urn:chokr:org:acme:agent:buyer"
HELPER = "urn:chokr:org:acme:agent:helper"
THIRD = "urn:chokr:org:acme:agent:third"
SELLER = "urn:chokr:org:acme:agent:seller"


def key_urn(key: Key) -> str:
    members = {k: key.jwk[k] for k in ("crv", "kty", "x")}
    text = json.dumps(members, sort_keys=True, separators=(",", ":"))
    return "urn:chokr:key:sha256:" + hashlib.sha256(text.encode()).hexdigest()


AGENT_URN = key_urn(KEYS["agent"])


# ---- documents -----------------------------------------------------------------------------------------------------

written: dict[str, dict[str, Any]] = {}


def write(area: str, name: str, kind: str, description: str, given: dict[str, Any], expected: dict[str, Any]) -> None:
    """One vector. `kind` is `valid`, `invalid` or `tamper` (a signed document changed after it was signed)."""
    vector = {
        "id": f"{area}/{name}",
        "level": "trust",
        "class": kind,
        "description": description,
        "input": given,
        "expected": expected,
    }
    actual = COMPUTE[area](vector, Context(schemas=data_dir() / "schemas"))
    shown = json.dumps(actual, sort_keys=True, default=str)[:400]
    if not subset(expected, actual):
        sys.exit(f"{area}/{name}: expected {json.dumps(expected, sort_keys=True)[:300]}, the checker gives {shown}")
    written[f"{area}/{name}"] = vector


def subset(expected: Any, actual: Any) -> bool:
    return _subset(expected, actual)


def signed(document: dict[str, Any], key: Key, **kwargs: str) -> dict[str, Any]:
    body = {k: v for k, v in document.items() if k not in ("signature", "proofs")}
    return {**body, "signature": key.signature(jcs(body), **kwargs)}


def hybrid(document: dict[str, Any], *keys: Key) -> dict[str, Any]:
    body = {k: v for k, v in document.items() if k not in ("signature", "proofs")}
    return {**body, "proofs": [k.signature(jcs(body)) for k in keys]}


def change(document: dict[str, Any], **members: Any) -> dict[str, Any]:
    out = copy.deepcopy(document)
    out.update(members)
    return out


def trust_config(
    extra_keys: list[tuple[str, Key]] | None = None,
    trust: list[dict[str, Any]] | None = None,
    status: dict[str, str] | None = None,
    only_keys: list[tuple[str, Key]] | None = None,
) -> dict[str, Any]:
    pairs = only_keys or [
        ("org:acme", KEYS["acme"]),
        ("org:acme", KEYS["acme_p256"]),
        ("org:acme", KEYS["acme_pq"]),
        ("org:acme", KEYS["acme_rsa"]),
        ("org:auditor", KEYS["auditor"]),
        ("org:other", KEYS["other"]),
        *(extra_keys or []),
    ]
    default_trust = [
        {"issuer": "org:acme", "evidence_type": "*"},
        {"issuer": "org:auditor", "evidence_type": "SECURITY_ASSESSMENT", "max_age_days": 30},
        {"issuer": "org:other", "evidence_type": "*"},
    ]
    config: dict[str, Any] = {
        "schema_version": "1.0",
        "issuer_keys": [{"issuer": issuer, "key": key.jwk} for issuer, key in pairs],
        "trust": default_trust if trust is None else trust,
    }
    if status:
        config["status"] = status
    return config


def credential_doc(**members: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "schema_version": "1.0",
        "type": "CapabilityCredential",
        "id": "cred-1",
        "issuer": "org:acme",
        "subject": BUYER,
        "issued_at": ISSUED,
        "expires_at": EXPIRES,
        "capabilities": [
            {
                "action": "app:transfer",
                "resource_type": "account",
                "constraints": [{"path": "attributes.quantity.value", "op": "lte", "value": 5000}],
            }
        ],
    }
    return {**base, **members}


def request(document: dict[str, Any], **more: Any) -> dict[str, Any]:
    return {"trust": trust_config(), "document": document, "now": NOW, **more}


# ---- thumbprint ----------------------------------------------------------------------------------------------------


def thumbprint_vectors() -> None:
    def expect(jwk: dict[str, Any], members: tuple[str, ...]) -> dict[str, str]:
        text = json.dumps({m: jwk[m] for m in members}, sort_keys=True, separators=(",", ":"))
        return {"thumbprint": "sha256:" + hashlib.sha256(text.encode()).hexdigest()}

    rfc_n = (
        "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3ok"
        "njhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6q"
        "MQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awap"
        "JzKnqDKgw"
    )
    rfc = {"kty": "RSA", "n": rfc_n, "e": "AQAB", "alg": "RS256", "kid": "2011-04-29"}
    rfc_thumb = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"  # printed in RFC 7638 section 3.1
    printed = base64.urlsafe_b64encode(bytes.fromhex(expect(rfc, ("e", "kty", "n"))["thumbprint"][7:]))
    if printed.decode().rstrip("=") != rfc_thumb:
        sys.exit("the RFC 7638 example key does not give the thumbprint the RFC prints")
    write(
        "thumbprint",
        "rfc7638_rsa_example",
        "valid",
        "The RSA key of RFC 7638 section 3.1 gives the thumbprint the RFC prints.",
        {"jwk": rfc},
        expect(rfc, ("e", "kty", "n")),
    )
    write(
        "thumbprint",
        "ed25519",
        "valid",
        "OKP: the members crv, kty, x.",
        {"jwk": KEYS["acme"].jwk},
        expect(KEYS["acme"].jwk, ("crv", "kty", "x")),
    )
    write(
        "thumbprint",
        "p256",
        "valid",
        "EC: the members crv, kty, x, y.",
        {"jwk": KEYS["acme_p256"].jwk},
        expect(KEYS["acme_p256"].jwk, ("crv", "kty", "x", "y")),
    )
    write(
        "thumbprint",
        "rsa_2048",
        "valid",
        "RSA: the members e, kty, n.",
        {"jwk": KEYS["acme_rsa"].jwk},
        expect(KEYS["acme_rsa"].jwk, ("e", "kty", "n")),
    )
    write(
        "thumbprint",
        "ml_dsa_44",
        "valid",
        "AKP: the members alg, kty, pub.",
        {"jwk": KEYS["acme_pq"].jwk},
        expect(KEYS["acme_pq"].jwk, ("alg", "kty", "pub")),
    )
    only = {k: v for k, v in KEYS["acme"].jwk.items() if k in ("kty", "crv", "x")}
    write(
        "thumbprint",
        "members_other_than_the_required_ones_are_ignored",
        "valid",
        "kid, alg and use do not change the thumbprint.",
        {"jwk": {**only, "kid": "other-name", "use": "sig"}},
        expect(KEYS["acme"].jwk, ("crv", "kty", "x")),
    )


# ---- crypto --------------------------------------------------------------------------------------------------------


def crypto_vectors() -> None:
    payload = {"action": "app:transfer", "amount": 100, "to": "acct-2"}
    message = jcs(payload)
    for name in ("acme", "acme_p256", "acme_rsa", "acme_pq"):
        key = KEYS[name]
        slug = key.alg.lower().replace("-", "")
        write(
            "crypto",
            f"{slug}_valid",
            "valid",
            f"A {key.alg} signature over the canonical payload verifies.",
            {"payload": payload, "signature": key.signature(message), "keys": [key.jwk]},
            {"valid": True},
        )
        altered = {**payload, "amount": 101}
        write(
            "crypto",
            f"{slug}_payload_changed",
            "tamper",
            f"A {key.alg} signature does not verify once the payload changed.",
            {"payload": altered, "signature": key.signature(message), "keys": [key.jwk]},
            {"valid": False, "code": "SIGNATURE_INVALID"},
        )
    for level in ("65", "87"):
        key = mldsa_key(f"pq-{level}", level)
        write(
            "crypto",
            f"ml_dsa_{level}_valid",
            "valid",
            f"An ML-DSA-{level} signature verifies.",
            {"payload": payload, "signature": key.signature(message), "keys": [key.jwk]},
            {"valid": True},
        )
    ed = KEYS["acme"]
    write(
        "crypto",
        "key_order_does_not_matter",
        "valid",
        "The signature is over the canonical form, so member order is free.",
        {
            "payload": {"to": "acct-2", "amount": 100, "action": "app:transfer"},
            "signature": ed.signature(message),
            "keys": [ed.jwk],
        },
        {"valid": True},
    )
    write(
        "crypto",
        "algorithm_confusion_is_refused",
        "invalid",
        "A signature that names ES256 for an Ed25519 key is refused: the key's algorithm is the only one used.",
        {"payload": payload, "signature": ed.signature(message, alg="ES256"), "keys": [ed.jwk]},
        {"valid": False, "code": "SIGNATURE_INVALID"},
    )
    for alg in ("none", "HS256"):
        write(
            "crypto",
            f"algorithm_{alg.lower()}_is_refused",
            "invalid",
            f"The algorithm name {alg} is never accepted.",
            {"payload": payload, "signature": ed.signature(message, alg=alg), "keys": [ed.jwk]},
            {"valid": False, "code": "SIGNATURE_INVALID"},
        )
    write(
        "crypto",
        "wrong_key",
        "invalid",
        "A signature by one key does not verify under another key with the same kid.",
        {"payload": payload, "signature": ed.signature(message), "keys": [{**KEYS["mallory"].jwk, "kid": ed.kid}]},
        {"valid": False, "code": "SIGNATURE_INVALID"},
    )
    write(
        "crypto",
        "unknown_kid",
        "invalid",
        "A kid that no key has.",
        {"payload": payload, "signature": ed.signature(message, kid="nobody"), "keys": [ed.jwk]},
        {"valid": False, "code": "KEY_NOT_FOUND"},
    )
    p256 = KEYS["acme_p256"]
    raw = p256.sign(message)
    der_value = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    write(
        "crypto",
        "es256_der_signature_is_refused",
        "invalid",
        "ES256 is the 64-byte R||S form; a DER signature is not.",
        {
            "payload": payload,
            "signature": {"alg": "ES256", "kid": p256.kid, "value": b64u(der_value)},
            "keys": [p256.jwk],
        },
        {"valid": False, "code": "SIGNATURE_INVALID"},
    )
    write(
        "crypto",
        "es256_short_signature_is_refused",
        "invalid",
        "A signature of the wrong length.",
        {
            "payload": payload,
            "signature": {"alg": "ES256", "kid": p256.kid, "value": b64u(raw[:63])},
            "keys": [p256.jwk],
        },
        {"valid": False, "code": "SIGNATURE_INVALID"},
    )
    small = rsa_signing_key("small-rsa", 1024)
    write(
        "crypto",
        "rs256_key_under_2048_bits_is_refused",
        "invalid",
        "An RSA key of 1024 bits is not accepted.",
        {"payload": payload, "signature": small.signature(message), "keys": [small.jwk]},
        {"valid": False, "code": "UNSUPPORTED_ALGORITHM"},
    )
    rsa_k = KEYS["acme_rsa"]
    write(
        "crypto",
        "rs256_exponent_other_than_65537_is_refused",
        "invalid",
        "An RSA key with e = 3 is not accepted.",
        {"payload": payload, "signature": rsa_k.signature(message), "keys": [{**rsa_k.jwk, "e": "Aw"}]},
        {"valid": False, "code": "UNSUPPORTED_ALGORITHM"},
    )
    write(
        "crypto",
        "signature_with_padding_is_refused",
        "invalid",
        "The signature is strict unpadded base64url.",
        {
            "payload": payload,
            "signature": {**ed.signature(message), "value": ed.signature(message)["value"] + "=="},
            "keys": [ed.jwk],
        },
        {"valid": False, "code": "SIGNATURE_INVALID"},
    )
    pq = KEYS["acme_pq"]
    both = {"payload": payload, "proofs": [ed.signature(message), pq.signature(message)], "keys": [ed.jwk, pq.jwk]}
    write(
        "crypto",
        "hybrid_ed25519_and_ml_dsa_valid",
        "valid",
        "Both proofs of a hybrid signature verify.",
        both,
        {"valid": True},
    )
    write(
        "crypto",
        "hybrid_without_the_post_quantum_proof",
        "invalid",
        "Removing the post-quantum proof leaves one proof, and a hybrid signature needs both.",
        {**both, "proofs": both["proofs"][:1]},
        {"valid": False, "code": "SCHEMA_INVALID"},
    )
    write(
        "crypto",
        "hybrid_with_a_forged_post_quantum_proof",
        "tamper",
        "Every proof must verify, not just one.",
        {**both, "proofs": [both["proofs"][0], {**both["proofs"][1], "value": b64u(b"\0" * 2420)}]},
        {"valid": False, "code": "SIGNATURE_INVALID"},
    )


# ---- compact JWS ---------------------------------------------------------------------------------------------------


def compact(header: dict[str, Any], claims: dict[str, Any], key: Key) -> str:
    h = b64u(json.dumps(header, sort_keys=True, separators=(",", ":")).encode())
    p = b64u(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode())
    return f"{h}.{p}.{b64u(key.sign(f'{h}.{p}'.encode()))}"


def jws_vectors() -> None:
    claims = {"iss": "org:acme", "sub": BUYER, "iat": NOW_EPOCH - 60, "nbf": NOW_EPOCH - 60, "exp": NOW_EPOCH + 3600}
    names = {"Ed25519": "EdDSA", "ES256": "ES256", "RS256": "RS256", "ML-DSA-44": "ML-DSA-44"}
    for name in ("acme", "acme_p256", "acme_rsa", "acme_pq"):
        key = KEYS[name]
        token = compact({"alg": names[key.alg], "kid": key.kid, "typ": "JWT"}, claims, key)
        write(
            "jws",
            f"{key.alg.lower().replace('-', '')}_valid",
            "valid",
            f"A compact JWS signed with {key.alg}.",
            {"token": token, "keys": [key.jwk], "now": NOW_EPOCH},
            {"accepted": True, "claims": claims},
        )
    ed = KEYS["acme"]
    header = {"alg": "EdDSA", "kid": ed.kid, "typ": "JWT"}
    good = compact(header, claims, ed)
    write(
        "jws",
        "single_key_needs_no_kid",
        "valid",
        "With one configured key a token without kid uses it.",
        {"token": compact({"alg": "EdDSA", "typ": "JWT"}, claims, ed), "keys": [ed.jwk], "now": NOW_EPOCH},
        {"accepted": True},
    )
    write(
        "jws",
        "tampered_payload",
        "tamper",
        "One byte of the payload changed after signing.",
        {
            "token": good.split(".")[0]
            + "."
            + b64u(json.dumps({**claims, "sub": THIRD}, sort_keys=True, separators=(",", ":")).encode())
            + "."
            + good.split(".")[2],
            "keys": [ed.jwk],
            "now": NOW_EPOCH,
        },
        {"accepted": False, "code": "SIGNATURE_INVALID"},
    )
    sig = good.split(".")[2]

    def with_header(h: dict[str, Any]) -> str:
        return (
            b64u(json.dumps(h, sort_keys=True, separators=(",", ":")).encode()) + "." + good.split(".")[1] + "." + sig
        )

    for alg in ("none", "HS256", "eddsa", "Ed25519", "ES256"):
        write(
            "jws",
            f"header_algorithm_{alg.lower()}_is_refused",
            "invalid",
            f"The header says {alg}, but the key is bound to EdDSA.",
            {"token": with_header({**header, "alg": alg}), "keys": [ed.jwk], "now": NOW_EPOCH},
            {"accepted": False, "code": "JWS_ALG_MISMATCH"},
        )
    for member, value in (("jwk", ed.jwk), ("jku", "https://keys.example/jwks"), ("x5c", ["AAAA"]), ("crit", ["exp"])):
        write(
            "jws",
            f"header_{member}_is_refused",
            "invalid",
            f"A header with {member} is refused: the key never comes from the token.",
            {"token": with_header({**header, member: value}), "keys": [ed.jwk], "now": NOW_EPOCH},
            {"accepted": False, "code": "SCHEMA_INVALID"},
        )
    write(
        "jws",
        "unknown_kid",
        "invalid",
        "A kid that no key has.",
        {"token": with_header({**header, "kid": "nobody"}), "keys": [ed.jwk], "now": NOW_EPOCH},
        {"accepted": False, "code": "JWS_KID_UNKNOWN"},
    )
    write(
        "jws",
        "two_keys_and_no_kid",
        "invalid",
        "Without a kid the key is only chosen when there is exactly one.",
        {
            "token": compact({"alg": "EdDSA", "typ": "JWT"}, claims, ed),
            "keys": [ed.jwk, KEYS["other"].jwk],
            "now": NOW_EPOCH,
        },
        {"accepted": False, "code": "JWS_KID_UNKNOWN"},
    )
    h, p, _ = good.split(".")
    for name, token in (
        ("padded_segment", f"{h}=.{p}.{sig}"),
        ("four_segments", f"{good}.AAAA"),
        ("empty_signature", f"{h}.{p}."),
        ("two_segments", f"{h}.{p}"),
        ("whitespace", f"{h} .{p}.{sig}"),
    ):
        write(
            "jws",
            f"malformed_{name}",
            "invalid",
            "Exactly three non-empty strict base64url segments.",
            {"token": token, "keys": [ed.jwk], "now": NOW_EPOCH},
            {"accepted": False, "code": "SCHEMA_INVALID"},
        )
    p256 = KEYS["acme_p256"]
    h2, p2 = (
        b64u(json.dumps({"alg": "ES256", "kid": p256.kid}, sort_keys=True, separators=(",", ":")).encode()),
        b64u(b"{}"),
    )
    raw = p256.sign(f"{h2}.{p2}".encode())
    der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    write(
        "jws",
        "es256_der_signature_is_refused",
        "invalid",
        "ES256 signatures are R||S, not DER.",
        {"token": f"{h2}.{p2}.{b64u(der)}", "keys": [p256.jwk], "now": NOW_EPOCH},
        {"accepted": False, "code": "SIGNATURE_INVALID"},
    )
    small = rsa_signing_key("small-rsa", 1024)
    write(
        "jws",
        "rs256_key_under_2048_bits_is_refused",
        "invalid",
        "An RSA key under 2048 bits.",
        {"token": compact({"alg": "RS256", "kid": small.kid}, claims, small), "keys": [small.jwk], "now": NOW_EPOCH},
        {"accepted": False, "code": "UNSUPPORTED_ALGORITHM"},
    )
    for delta, verdict in ((29, True), (30, False)):
        write(
            "jws",
            f"expired_{delta}_seconds_ago",
            "valid" if verdict else "invalid",
            f"exp passed {delta} s ago: valid until exp plus 30 s, so " + ("still valid." if verdict else "expired."),
            {"token": compact(header, {**claims, "exp": NOW_EPOCH - delta}, ed), "keys": [ed.jwk], "now": NOW_EPOCH},
            {"accepted": True} if verdict else {"accepted": False, "code": "CREDENTIAL_EXPIRED"},
        )
    for delta, verdict in ((30, True), (31, False)):
        write(
            "jws",
            f"not_before_{delta}_seconds_ahead",
            "valid" if verdict else "invalid",
            f"nbf is {delta} s ahead: valid from nbf minus 30 s, so "
            + ("already valid." if verdict else "not yet valid."),
            {"token": compact(header, {**claims, "nbf": NOW_EPOCH + delta}, ed), "keys": [ed.jwk], "now": NOW_EPOCH},
            {"accepted": True} if verdict else {"accepted": False, "code": "CREDENTIAL_NOT_YET_VALID"},
        )
    write(
        "jws",
        "tolerance_is_configurable",
        "valid",
        "With a tolerance of 60 s a token 59 s past exp is accepted.",
        {
            "token": compact(header, {**claims, "exp": NOW_EPOCH - 59}, ed),
            "keys": [ed.jwk],
            "now": NOW_EPOCH,
            "clock_skew_seconds": 60,
        },
        {"accepted": True},
    )
    write(
        "jws",
        "tolerance_above_300_is_refused",
        "invalid",
        "A tolerance over 300 s is a configuration error.",
        {"token": good, "keys": [ed.jwk], "now": NOW_EPOCH, "clock_skew_seconds": 301},
        {"accepted": False, "code": "SCHEMA_INVALID"},
    )


# ---- credential ----------------------------------------------------------------------------------------------------


def credential_vectors() -> None:
    acme = KEYS["acme"]
    good = signed(credential_doc(), acme)
    write(
        "credential",
        "valid",
        "valid",
        "A credential signed by a key of its trusted issuer.",
        request(good),
        {"accepted": True},
    )
    write(
        "credential",
        "valid_second_key_of_the_issuer",
        "valid",
        "An issuer can have several keys.",
        request(signed(credential_doc(), KEYS["acme_p256"])),
        {"accepted": True},
    )
    write(
        "credential",
        "valid_hybrid_proofs",
        "valid",
        "A credential with two proofs, both of which verify.",
        request(hybrid(credential_doc(), acme, KEYS["acme_pq"])),
        {"accepted": True},
    )
    write(
        "credential",
        "valid_for_the_subject_asked_about",
        "valid",
        "The subject matches.",
        request(good, subject=BUYER),
        {"accepted": True},
    )
    with_aud = signed(credential_doc(audience=SELLER), acme)
    write(
        "credential",
        "valid_audience_matches",
        "valid",
        "The audience matches.",
        request(with_aud, audience=SELLER),
        {"accepted": True},
    )
    write(
        "credential",
        "valid_without_audience_accepts_any",
        "valid",
        "A credential without audience accepts any audience.",
        request(good, audience="anyone"),
        {"accepted": True},
    )
    write(
        "credential",
        "valid_one_second_inside_the_window_end",
        "valid",
        "expires_at plus the 30 s tolerance is still in the future.",
        request(signed(credential_doc(expires_at="2026-06-01T11:59:31Z"), acme)),
        {"accepted": True},
    )
    write(
        "credential",
        "valid_at_the_window_start",
        "valid",
        "issued_at minus the tolerance is exactly now.",
        request(signed(credential_doc(issued_at="2026-06-01T12:00:30Z"), acme)),
        {"accepted": True},
    )
    write(
        "credential",
        "expired_at_the_window_end",
        "invalid",
        "now is exactly expires_at plus the tolerance: expired.",
        request(signed(credential_doc(expires_at="2026-06-01T11:59:30Z"), acme)),
        {"accepted": False, "code": "CREDENTIAL_EXPIRED"},
    )
    write(
        "credential",
        "not_yet_valid_one_second_before_the_start",
        "invalid",
        "issued_at is 31 s ahead.",
        request(signed(credential_doc(issued_at="2026-06-01T12:00:31Z"), acme)),
        {"accepted": False, "code": "CREDENTIAL_NOT_YET_VALID"},
    )
    write(
        "credential",
        "tolerance_of_zero",
        "invalid",
        "With no tolerance a credential that expired 1 s ago is expired.",
        request(signed(credential_doc(expires_at="2026-06-01T11:59:59Z"), acme), clock_skew_seconds=0),
        {"accepted": False, "code": "CREDENTIAL_EXPIRED"},
    )
    write(
        "credential",
        "tolerance_above_300_is_refused",
        "invalid",
        "A tolerance over 300 s fails the configuration.",
        request(good, clock_skew_seconds=301),
        {"accepted": False, "code": "SCHEMA_INVALID"},
    )
    write(
        "credential",
        "unknown_kid",
        "invalid",
        "No key of any issuer has the kid.",
        request(signed(credential_doc(), acme, kid="nobody")),
        {"accepted": False, "code": "KEY_NOT_FOUND"},
    )
    write(
        "credential",
        "key_of_another_issuer",
        "invalid",
        "The kid belongs to org:other, not to the issuer named.",
        request(signed(credential_doc(), KEYS["other"])),
        {"accepted": False, "code": "ISSUER_MISMATCH"},
    )
    write(
        "credential",
        "field_changed_after_signing",
        "tamper",
        "The subject was changed after signing.",
        request(change(good, subject=THIRD)),
        {"accepted": False, "code": "SIGNATURE_INVALID"},
    )
    write(
        "credential",
        "capability_widened_after_signing",
        "tamper",
        "A capability bound was raised after signing.",
        request(json.loads(json.dumps(good).replace("5000", "5001"))),
        {"accepted": False, "code": "SIGNATURE_INVALID"},
    )
    write(
        "credential",
        "signature_names_another_algorithm",
        "invalid",
        "A signature that claims ES256 for an Ed25519 key.",
        request(signed(credential_doc(), acme, alg="ES256")),
        {"accepted": False, "code": "SIGNATURE_INVALID"},
    )
    write(
        "credential",
        "signature_algorithm_none",
        "invalid",
        "alg none is never accepted.",
        request(signed(credential_doc(), acme, alg="none")),
        {"accepted": False, "code": "SCHEMA_INVALID"},
    )
    write(
        "credential",
        "key_revoked",
        "invalid",
        "The signature verifies, but the key has been revoked.",
        {**request(good), "trust": trust_config(status={key_urn(acme): "REVOKED"})},
        {"accepted": False, "code": "KEY_REVOKED"},
    )
    write(
        "credential",
        "issuer_not_trusted",
        "invalid",
        "The key belongs to the issuer, but nobody trusts the issuer.",
        {**request(good), "trust": trust_config(trust=[])},
        {"accepted": False, "code": "ISSUER_UNTRUSTED"},
    )
    write(
        "credential",
        "issuer_trusted_only_for_one_evidence_type",
        "invalid",
        "Trust for one evidence type is not trust for credentials.",
        {**request(good), "trust": trust_config(trust=[{"issuer": "org:acme", "evidence_type": "COMPLIANCE"}])},
        {"accepted": False, "code": "ISSUER_UNTRUSTED"},
    )
    write(
        "credential",
        "subject_mismatch",
        "invalid",
        "The credential is for another subject.",
        request(good, subject=THIRD),
        {"accepted": False, "code": "SUBJECT_MISMATCH"},
    )
    write(
        "credential",
        "audience_mismatch",
        "invalid",
        "The credential names another audience.",
        request(with_aud, audience="urn:chokr:org:acme:agent:other"),
        {"accepted": False, "code": "AUDIENCE_MISMATCH"},
    )
    write(
        "credential",
        "audience_required_but_not_supplied",
        "invalid",
        "A credential with an audience, verified without one, fails closed.",
        request(with_aud),
        {"accepted": False, "code": "AUDIENCE_MISMATCH"},
    )
    write(
        "credential",
        "credential_revoked",
        "invalid",
        "The credential id has been revoked.",
        {**request(good), "trust": trust_config(status={"cred-1": "REVOKED"})},
        {"accepted": False, "code": "CREDENTIAL_REVOKED"},
    )
    write(
        "credential",
        "subject_suspended",
        "invalid",
        "The subject has been suspended.",
        {**request(good), "trust": trust_config(status={BUYER: "SUSPENDED"})},
        {"accepted": False, "code": "CREDENTIAL_REVOKED"},
    )
    write(
        "credential",
        "first_failing_check_decides_expired_before_subject",
        "invalid",
        "Expired and for another subject: the validity window is checked first.",
        request(signed(credential_doc(expires_at="2026-05-02T00:00:00Z"), acme), subject=THIRD),
        {"accepted": False, "code": "CREDENTIAL_EXPIRED"},
    )
    write(
        "credential",
        "first_failing_check_decides_signature_before_issuer_trust",
        "invalid",
        "A bad signature by an untrusted issuer is a signature failure.",
        {**request(change(good, subject=THIRD)), "trust": trust_config(trust=[])},
        {"accepted": False, "code": "SIGNATURE_INVALID"},
    )
    unsigned_doc = {k: v for k, v in good.items() if k != "signature"}
    write(
        "credential",
        "unsigned",
        "invalid",
        "A credential with no signature.",
        request(unsigned_doc),
        {"accepted": False, "code": "SCHEMA_INVALID"},
    )
    bad_op = credential_doc()
    bad_op["capabilities"][0]["constraints"][0]["op"] = "approx"
    write(
        "credential",
        "unknown_constraint_operator",
        "invalid",
        "An unknown operator is refused when the credential is verified.",
        request(signed(bad_op, acme)),
        {"accepted": False, "code": "SCHEMA_INVALID"},
    )
    bad_path = credential_doc()
    bad_path["capabilities"][0]["constraints"][0]["path"] = "claims.anything"
    write(
        "credential",
        "constraint_path_outside_the_standard_set",
        "invalid",
        "A path outside the standard set.",
        request(signed(bad_path, acme)),
        {"accepted": False, "code": "SCHEMA_INVALID"},
    )
    write(
        "credential",
        "timestamp_with_an_offset",
        "invalid",
        "Timestamps are UTC with Z.",
        request(signed(credential_doc(expires_at="2026-07-01T02:00:00+02:00"), acme)),
        {"accepted": False, "code": "SCHEMA_INVALID"},
    )
    rebound = trust_config()
    rebound["issuer_keys"].append({"issuer": "org:other", "key": acme.jwk})
    write(
        "credential",
        "kid_rebound_to_another_issuer",
        "invalid",
        "A trust config that gives one kid to two issuers is refused.",
        {**request(good), "trust": rebound},
        {"accepted": False, "code": "SCHEMA_INVALID"},
    )


# ---- delegation ----------------------------------------------------------------------------------------------------


def grant(
    action: str = "app:transfer", resource: str = "account", *constraints: tuple[str, str, Any]
) -> dict[str, Any]:
    return {
        "action": action,
        "resource_type": resource,
        "constraints": [{"path": p, "op": o, "value": v} for p, o, v in constraints],
    }


QUANTITY = "attributes.quantity.value"


def link(
    delegator: str, delegatee: str, grants: list[dict[str, Any]], key: Key | None = None, **members: Any
) -> dict[str, Any]:
    body = {
        "schema_version": "1.0",
        "type": "Delegation",
        "id": members.pop("id", f"del-{delegator[-5:]}-{delegatee[-5:]}"),
        "delegator": delegator,
        "delegatee": delegatee,
        "issuer": members.pop("issuer", "org:acme"),
        "grant": grants,
        "issued_at": ISSUED,
        "expires_at": EXPIRES,
        **members,
    }
    return signed(body, key or KEYS["acme"])


def delegation_request(chain: list[dict[str, Any]], leaf: str, **more: Any) -> dict[str, Any]:
    return {"trust": trust_config(), "chain": chain, "leaf_subject": leaf, "now": NOW, **more}


def delegation_vectors() -> None:
    wide = [grant("app:transfer", "account", (QUANTITY, "lte", 5000), ("audience", "eq", SELLER))]
    one = link(BUYER, HELPER, wide)
    write(
        "delegation",
        "valid_single_link",
        "valid",
        "One delegation from the delegator to the leaf.",
        delegation_request([one], HELPER),
        {"accepted": True},
    )
    narrow = [
        grant(
            "app:transfer", "account", (QUANTITY, "lte", 1000), ("audience", "eq", SELLER), ("purpose", "eq", "payroll")
        )
    ]
    first = link(BUYER, HELPER, wide, max_depth=2)
    second = link(HELPER, THIRD, narrow)
    write(
        "delegation",
        "valid_two_links_attenuated",
        "valid",
        "The child lowers a bound and adds a constraint on a new path: narrower on both counts.",
        delegation_request([first, second], THIRD, max_depth=2),
        {"accepted": True},
    )
    sets = [grant("app:read", "doc", ("resource.id", "in", ["a", "b", "c"]), ("purpose", "nin", ["x"]))]
    narrower_sets = [grant("app:read", "doc", ("resource.id", "in", ["a", "b"]), ("purpose", "nin", ["x", "y"]))]
    write(
        "delegation",
        "valid_set_constraints_narrow",
        "valid",
        "`in` shrinks and `nin` grows.",
        delegation_request(
            [link(BUYER, HELPER, sets, max_depth=2), link(HELPER, THIRD, narrower_sets)], THIRD, max_depth=2
        ),
        {"accepted": True},
    )
    write(
        "delegation",
        "valid_equal_constraints",
        "valid",
        "An equal value is narrow enough.",
        delegation_request([link(BUYER, HELPER, wide, max_depth=2), link(HELPER, THIRD, wide)], THIRD, max_depth=2),
        {"accepted": True},
    )
    # self-verifying path
    agent = KEYS["agent"]
    keyed = link(AGENT_URN, HELPER, wide, agent, issuer=AGENT_URN, keys=[agent.jwk])
    write(
        "delegation",
        "valid_self_certifying",
        "valid",
        "The delegator is the key id of the embedded key that signed, and it is also the issuer.",
        {**delegation_request([keyed], HELPER), "trust": trust_config(trust=[])},
        {"accepted": True},
    )
    forged = link(BUYER, HELPER, wide, KEYS["mallory"], issuer=BUYER, keys=[KEYS["mallory"].jwk])
    write(
        "delegation",
        "self_certifying_forgery_names_a_victim",
        "invalid",
        "An attacker embeds their own key and names a victim as delegator and issuer: it is not self-certifying "
        "and the key is not known.",
        delegation_request([forged], HELPER),
        {"accepted": False, "code": "KEY_NOT_FOUND"},
    )

    def escalate(child_grants: list[dict[str, Any]], code: str, name: str, description: str) -> None:
        write(
            "delegation",
            name,
            "invalid",
            description,
            delegation_request(
                [link(BUYER, HELPER, wide, max_depth=2), link(HELPER, THIRD, child_grants)], THIRD, max_depth=2
            ),
            {"accepted": False, "code": code},
        )

    escalate(
        [grant("app:transfer", "account", (QUANTITY, "lte", 6000), ("audience", "eq", SELLER))],
        "CONSTRAINT_VIOLATED",
        "escalation_wider_bound",
        "The child raises the numeric bound.",
    )
    escalate(
        [grant("app:transfer", "account", (QUANTITY, "lte", 5000))],
        "AUDIENCE_OUT_OF_SCOPE",
        "escalation_dropped_audience",
        "The child drops the audience constraint.",
    )
    escalate(
        [grant("app:transfer", "account", ("audience", "eq", SELLER))],
        "CONSTRAINT_VIOLATED",
        "escalation_dropped_constraint",
        "The child drops the bound.",
    )
    escalate(
        [grant("app:transfer", "account", (QUANTITY, "lte", 100), ("audience", "eq", "somebody-else"))],
        "AUDIENCE_OUT_OF_SCOPE",
        "escalation_other_audience",
        "The child names another audience.",
    )
    escalate(
        [grant("app:delete", "account", (QUANTITY, "lte", 1))],
        "DELEGATION_ESCALATION",
        "escalation_new_action",
        "The child grants an action the parent never had.",
    )
    escalate(
        [grant("app:transfer", "vault", (QUANTITY, "lte", 1))],
        "DELEGATION_ESCALATION",
        "escalation_other_resource_type",
        "The child grants another resource type.",
    )
    escalate(
        [grant("app:transfer", "account", (QUANTITY, "eq", 10), ("audience", "eq", SELLER))],
        "CONSTRAINT_VIOLATED",
        "escalation_mixed_operator",
        "A different operator is covered only if identical.",
    )
    escalate(
        [grant("app:transfer", "account", (QUANTITY, "lte", "100"), ("audience", "eq", SELLER))],
        "CONSTRAINT_VIOLATED",
        "escalation_bound_is_not_a_number",
        "A bound that is not a number never counts as narrower.",
    )
    write(
        "delegation",
        "escalation_set_widened",
        "invalid",
        "`in` grows.",
        delegation_request(
            [
                link(BUYER, HELPER, sets, max_depth=2),
                link(
                    HELPER,
                    THIRD,
                    [grant("app:read", "doc", ("resource.id", "in", ["a", "b", "c", "d"]), ("purpose", "nin", ["x"]))],
                ),
            ],
            THIRD,
            max_depth=2,
        ),
        {"accepted": False, "code": "CONSTRAINT_VIOLATED"},
    )
    write(
        "delegation",
        "escalation_negated_set_shrunk",
        "invalid",
        "`nin` shrinks.",
        delegation_request(
            [
                link(BUYER, HELPER, sets, max_depth=2),
                link(HELPER, THIRD, [grant("app:read", "doc", ("resource.id", "in", ["a"]), ("purpose", "nin", []))]),
            ],
            THIRD,
            max_depth=2,
        ),
        {"accepted": False, "code": "CONSTRAINT_VIOLATED"},
    )
    # depth
    write(
        "delegation",
        "depth_two_links_with_default_max_depth",
        "invalid",
        "The first link allows depth 1; the chain has 2.",
        delegation_request([link(BUYER, HELPER, wide), link(HELPER, THIRD, narrow)], THIRD, max_depth=2),
        {"accepted": False, "code": "DELEGATION_DEPTH_EXCEEDED"},
    )
    write(
        "delegation",
        "depth_exceeds_the_argument",
        "invalid",
        "The caller allows depth 1; the chain has 2.",
        delegation_request([first, second], THIRD, max_depth=1),
        {"accepted": False, "code": "DELEGATION_DEPTH_EXCEEDED"},
    )
    third_hop = link(THIRD, SELLER, narrow, max_depth=1)
    write(
        "delegation",
        "depth_exceeds_the_hard_ceiling",
        "invalid",
        "Every link claims a large depth, but the absolute ceiling is 2.",
        delegation_request(
            [link(BUYER, HELPER, wide, max_depth=5), link(HELPER, THIRD, narrow, max_depth=5), third_hop],
            SELLER,
            max_depth=5,
            max_chain_depth=2,
        ),
        {"accepted": False, "code": "DELEGATION_DEPTH_EXCEEDED"},
    )
    write(
        "delegation",
        "depth_at_the_hard_ceiling",
        "valid",
        "A chain exactly as long as the ceiling.",
        delegation_request([first, second], THIRD, max_depth=2, max_chain_depth=2),
        {"accepted": True},
    )
    # chain shape
    write(
        "delegation",
        "leaf_is_not_the_subject",
        "invalid",
        "The last delegatee is not the subject of the request.",
        delegation_request([one], THIRD),
        {"accepted": False, "code": "SUBJECT_MISMATCH"},
    )
    write(
        "delegation",
        "links_do_not_connect",
        "invalid",
        "A delegatee that is not the next delegator.",
        delegation_request([first, link(THIRD, SELLER, narrow)], SELLER, max_depth=2),
        {"accepted": False, "code": "SUBJECT_MISMATCH"},
    )
    write(
        "delegation",
        "same_delegation_twice_is_a_cycle",
        "invalid",
        "A repeated id is a cycle.",
        delegation_request(
            [link(BUYER, HELPER, wide, max_depth=2, id="same"), link(HELPER, THIRD, narrow, id="same")],
            THIRD,
            max_depth=2,
        ),
        {"accepted": False, "code": "DELEGATION_ESCALATION"},
    )
    write(
        "delegation",
        "empty_chain",
        "invalid",
        "A chain has at least one link.",
        delegation_request([], HELPER),
        {"accepted": False, "code": "SCHEMA_INVALID"},
    )
    # authority and trust
    write(
        "delegation",
        "issuer_does_not_own_the_delegator_namespace",
        "invalid",
        "org:other issued a delegation for a subject of org:acme.",
        delegation_request([link(BUYER, HELPER, wide, KEYS["other"], issuer="org:other")], HELPER),
        {"accepted": False, "code": "ISSUER_MISMATCH"},
    )
    write(
        "delegation",
        "issuer_not_trusted",
        "invalid",
        "The issuer's key is known but the issuer is not trusted.",
        {**delegation_request([one], HELPER), "trust": trust_config(trust=[])},
        {"accepted": False, "code": "ISSUER_UNTRUSTED"},
    )
    write(
        "delegation",
        "link_expired",
        "invalid",
        "A link past its expiry.",
        delegation_request([link(BUYER, HELPER, wide, expires_at="2026-05-02T00:00:00Z")], HELPER),
        {"accepted": False, "code": "CREDENTIAL_EXPIRED"},
    )
    write(
        "delegation",
        "delegator_revoked",
        "invalid",
        "The delegator has been revoked.",
        {**delegation_request([one], HELPER), "trust": trust_config(status={BUYER: "REVOKED"})},
        {"accepted": False, "code": "CREDENTIAL_REVOKED"},
    )
    write(
        "delegation",
        "grant_changed_after_signing",
        "tamper",
        "A bound was raised after the link was signed.",
        delegation_request([json.loads(json.dumps(one).replace("5000", "9000"))], HELPER),
        {"accepted": False, "code": "SIGNATURE_INVALID"},
    )
    write(
        "delegation",
        "delegatee_changed_after_signing",
        "tamper",
        "The delegatee was swapped after signing.",
        delegation_request([change(one, delegatee=THIRD)], THIRD),
        {"accepted": False, "code": "SIGNATURE_INVALID"},
    )


def delegation_bound_vectors() -> None:
    """Lower bounds and strict bounds: `gte` and `gt` may only rise, `lt` and `lte` only fall."""
    parent = [grant("app:read", "doc", ("resource.count", "gte", 10), ("attributes.age.value", "lt", 100))]
    first = link(BUYER, HELPER, parent, max_depth=2)

    def child(*constraints: tuple[str, str, Any]) -> list[dict[str, Any]]:
        return [grant("app:read", "doc", *constraints)]

    narrower = child(("resource.count", "gte", 20), ("attributes.age.value", "lt", 50))
    write(
        "delegation",
        "valid_lower_bound_raised_and_strict_bound_lowered",
        "valid",
        "gte rises and lt falls: narrower on both counts.",
        delegation_request([first, link(HELPER, THIRD, narrower)], THIRD, max_depth=2),
        {"accepted": True},
    )
    write(
        "delegation",
        "escalation_lower_bound_lowered",
        "invalid",
        "The child lowers a gte bound, which admits more.",
        delegation_request(
            [first, link(HELPER, THIRD, child(("resource.count", "gte", 5), ("attributes.age.value", "lt", 50)))],
            THIRD,
            max_depth=2,
        ),
        {"accepted": False, "code": "CONSTRAINT_VIOLATED"},
    )
    write(
        "delegation",
        "escalation_strict_bound_raised",
        "invalid",
        "The child raises an lt bound, which admits more.",
        delegation_request(
            [first, link(HELPER, THIRD, child(("resource.count", "gte", 20), ("attributes.age.value", "lt", 150)))],
            THIRD,
            max_depth=2,
        ),
        {"accepted": False, "code": "CONSTRAINT_VIOLATED"},
    )
    malformed = "urn:chokr:org:acme:agent:buyer:extra"
    write(
        "delegation",
        "delegator_native_id_with_a_colon_is_malformed",
        "invalid",
        "A part of a native id never contains a colon; it is rejected, not cut at the colon.",
        delegation_request([link(malformed, HELPER, parent)], HELPER),
        {"accepted": False, "code": "SCHEMA_INVALID"},
    )


# ---- evidence ------------------------------------------------------------------------------------------------------


def evidence_doc(**members: Any) -> dict[str, Any]:
    base = {
        "schema_version": "1.0",
        "type": "SECURITY_ASSESSMENT",
        "id": "ev-1",
        "issuer": "org:auditor",
        "subject": BUYER,
        "digest": "sha256:" + hashlib.sha256(b"report body").hexdigest(),
        "artifact_ref": "https://evidence.example/r.pdf",
        "status": "ACTIVE",
        "issued_at": "2026-05-20T00:00:00Z",
        "expires_at": EXPIRES,
    }
    return {**base, **members}


def evidence_vectors() -> None:
    aud = KEYS["auditor"]
    good = signed(evidence_doc(), aud)
    write(
        "evidence",
        "valid_fresh",
        "valid",
        "A trusted issuer, inside its window and its maximum age.",
        request(good),
        {"accepted": True, "status": "fresh"},
    )
    write(
        "evidence",
        "valid_without_expiry",
        "valid",
        "expires_at is optional.",
        request(signed({k: v for k, v in evidence_doc().items() if k != "expires_at"}, aud)),
        {"accepted": True, "status": "fresh"},
    )
    write(
        "evidence",
        "valid_artifact_matches_the_digest",
        "valid",
        "The fetched content hashes to the digest.",
        request(good, artifact="report body"),
        {"accepted": True, "status": "fresh"},
    )
    write(
        "evidence",
        "valid_custom_type_with_its_own_relationship",
        "valid",
        "A namespaced type, trusted for exactly that type.",
        {
            **request(signed(evidence_doc(type="com.acme/PEN_TEST_REPORT"), aud)),
            "trust": trust_config(trust=[{"issuer": "org:auditor", "evidence_type": "com.acme/PEN_TEST_REPORT"}]),
        },
        {"accepted": True, "status": "fresh"},
    )
    write(
        "evidence",
        "stale_older_than_the_maximum_age",
        "valid",
        "Issued 42 days ago with a maximum age of 30 days: authentic, reported stale.",
        request(signed(evidence_doc(issued_at="2026-04-20T00:00:00Z"), aud)),
        {"accepted": True, "status": "stale"},
    )
    write(
        "evidence",
        "age_exactly_the_maximum",
        "valid",
        "Issued exactly 30 days ago is still fresh.",
        request(signed(evidence_doc(issued_at="2026-05-02T12:00:00Z"), aud)),
        {"accepted": True, "status": "fresh"},
    )
    write(
        "evidence",
        "expired",
        "valid",
        "Past expires_at plus the tolerance: authentic, stale, with the expiry code.",
        request(signed(evidence_doc(expires_at="2026-06-01T11:59:30Z"), aud)),
        {"accepted": True, "status": "stale", "code": "EVIDENCE_EXPIRED"},
    )
    write(
        "evidence",
        "expired_but_inside_the_tolerance",
        "valid",
        "29 s past expires_at is fresh.",
        request(signed(evidence_doc(expires_at="2026-06-01T11:59:31Z"), aud)),
        {"accepted": True, "status": "fresh"},
    )
    write(
        "evidence",
        "issuer_trusted_for_another_type",
        "invalid",
        "Trusted for SECURITY_ASSESSMENT, not for COMPLIANCE.",
        request(signed(evidence_doc(type="COMPLIANCE"), aud)),
        {"accepted": False, "code": "ISSUER_UNTRUSTED"},
    )
    write(
        "evidence",
        "issuer_not_trusted",
        "invalid",
        "No relationship for the issuer.",
        {**request(good), "trust": trust_config(trust=[])},
        {"accepted": False, "code": "ISSUER_UNTRUSTED"},
    )
    write(
        "evidence",
        "digest_changed_after_signing",
        "tamper",
        "The digest was replaced after signing.",
        request(change(good, digest="sha256:" + "0" * 64)),
        {"accepted": False, "code": "SIGNATURE_INVALID"},
    )
    write(
        "evidence",
        "key_of_another_issuer",
        "invalid",
        "Signed by a key that belongs to org:acme.",
        request(signed(evidence_doc(), KEYS["acme"])),
        {"accepted": False, "code": "ISSUER_MISMATCH"},
    )
    write(
        "evidence",
        "artifact_does_not_match_the_digest",
        "invalid",
        "The fetched content hashes to something else.",
        request(good, artifact="another body"),
        {"accepted": False, "code": "EVIDENCE_INVALID"},
    )
    write(
        "evidence",
        "subject_mismatch",
        "invalid",
        "Evidence about another agent.",
        request(good, subject=THIRD),
        {"accepted": False, "code": "SUBJECT_MISMATCH"},
    )
    write(
        "evidence",
        "issued_in_the_future",
        "invalid",
        "issued_at is more than the tolerance ahead.",
        request(signed(evidence_doc(issued_at="2026-06-01T12:01:00Z"), aud)),
        {"accepted": False, "code": "EVIDENCE_INVALID"},
    )
    write(
        "evidence",
        "evidence_revoked",
        "invalid",
        "The evidence id has been revoked.",
        {**request(good), "trust": trust_config(status={"ev-1": "REVOKED"})},
        {"accepted": False, "code": "EVIDENCE_INVALID"},
    )
    write(
        "evidence",
        "lowercase_type",
        "invalid",
        "A standard type is upper case.",
        request(signed(evidence_doc(type="security_assessment"), aud)),
        {"accepted": False, "code": "SCHEMA_INVALID"},
    )


# ---- passport ------------------------------------------------------------------------------------------------------


def passport_doc(credentials: list[dict[str, Any]], evidence: list[dict[str, Any]], **members: Any) -> dict[str, Any]:
    base = {
        "schema_version": "1.0",
        "type": "AgentPassport",
        "issuer": "org:acme",
        "agent": {"id": BUYER, "organization": "acme", "version": "1.0.0"},
        "identifiers": [AGENT_URN],
        "credentials": credentials,
        "evidence": evidence,
        "status": "ACTIVE",
        "issued_at": ISSUED,
    }
    return {**base, **members}


def passport_vectors() -> None:
    acme, aud = KEYS["acme"], KEYS["auditor"]
    cred = signed(credential_doc(), acme)
    evid = signed(evidence_doc(), aud)
    good = signed(passport_doc([cred], [evid]), acme)
    write(
        "passport",
        "valid",
        "valid",
        "Every inner item and the outer signature verify.",
        request(good),
        {"ok": True, "outer_signature": True, "errors": []},
    )
    stale = signed(evidence_doc(issued_at="2026-04-20T00:00:00Z"), aud)
    write(
        "passport",
        "stale_evidence_does_not_fail_the_passport",
        "valid",
        "Stale evidence is reported, and ok stays true.",
        request(signed(passport_doc([cred], [stale]), acme)),
        {"ok": True, "evidence": [{"id": "ev-1", "status": "stale"}]},
    )
    other_id = signed(credential_doc(subject=AGENT_URN, id="cred-2"), acme)
    write(
        "passport",
        "valid_item_about_a_listed_identifier",
        "valid",
        "An item about an identifier the passport lists.",
        request(signed(passport_doc([cred, other_id], [evid]), acme)),
        {"ok": True},
    )
    expired = signed(credential_doc(expires_at="2026-05-02T00:00:00Z"), acme)
    write(
        "passport",
        "expired_credential_fails_the_passport",
        "invalid",
        "An expired inner credential.",
        request(signed(passport_doc([expired], [evid]), acme)),
        {"ok": False, "outer_signature": True, "errors": ["CREDENTIAL_EXPIRED"]},
    )
    stranger = signed(credential_doc(subject=THIRD, id="cred-3"), acme)
    write(
        "passport",
        "item_about_someone_else",
        "invalid",
        "One inner item is about another subject; the other items are still verified.",
        request(signed(passport_doc([stranger, cred], [evid]), acme)),
        {
            "ok": False,
            "errors": ["SUBJECT_MISMATCH"],
            "credentials": [
                {"id": "cred-3", "accepted": False, "code": "SUBJECT_MISMATCH"},
                {"id": "cred-1", "accepted": True},
            ],
            "evidence": [{"id": "ev-1", "accepted": True}],
        },
    )
    by_auditor = signed(passport_doc([cred], [evid], issuer="org:auditor"), aud)
    write(
        "passport",
        "outer_issuer_not_trusted_although_every_item_is_valid",
        "invalid",
        "A valid outer signature by an issuer that is trusted only for one evidence type.",
        request(by_auditor),
        {
            "ok": False,
            "outer_signature": False,
            "errors": ["ISSUER_UNTRUSTED"],
            "credentials": [{"id": "cred-1", "accepted": True}],
            "evidence": [{"id": "ev-1", "accepted": True}],
        },
    )
    forged = change(cred, id="cred-9")  # the item names the agent, but its signature covers the other id
    write(
        "passport",
        "outer_signature_does_not_stand_in_for_an_inner_one",
        "tamper",
        "The outer signature is valid but an inner credential was changed after it was signed.",
        request(signed(passport_doc([forged], [evid]), acme)),
        {
            "ok": False,
            "outer_signature": True,
            "errors": ["SIGNATURE_INVALID"],
            "credentials": [{"id": "cred-9", "accepted": False, "code": "SIGNATURE_INVALID"}],
        },
    )
    write(
        "passport",
        "outer_content_changed_after_signing",
        "tamper",
        "A field of the passport changed after signing.",
        request(change(good, status="SUSPENDED")),
        {"ok": False, "outer_signature": False, "errors": ["SIGNATURE_INVALID"]},
    )
    write(
        "passport",
        "unsigned_passport",
        "invalid",
        "No outer signature.",
        request({k: v for k, v in good.items() if k != "signature"}),
        {"ok": False, "errors": ["SCHEMA_INVALID"]},
    )


# ---- proof of possession and key binding ---------------------------------------------------------------------------


def challenge(nonce: str = "AAAAAAAAAAAAAAAAAAAAAA", **members: Any) -> dict[str, Any]:
    base = {
        "schema_version": "1.0",
        "type": "PoPChallenge",
        "subject": BUYER,
        "audience": SELLER,
        "nonce": nonce,
        "issued_at": "2026-06-01T11:59:00Z",
        "expires_at": "2026-06-01T12:01:00Z",
        "purpose": "tool:call",
    }
    return {**base, **members}


def proof(ch: dict[str, Any], key: Key) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "type": "PoPProof",
        "challenge": ch,
        "signature": key.signature(jcs(ch)),
        "key": key.jwk,
    }


def pop_vectors() -> None:
    agent = KEYS["agent"]
    ch = challenge()
    good = proof(ch, agent)
    base = {"trust": trust_config(), "challenges": [ch], "registry": {BUYER: [agent.jwk]}}
    ok = {"accepted": True}

    def case(
        name: str,
        kind: str,
        description: str,
        attempts: list[dict[str, Any]],
        results: list[dict[str, Any]],
        **more: Any,
    ) -> None:
        write("pop", name, kind, description, {**base, "attempts": attempts, **more}, {"results": results})

    attempt = {"proof": good, "now": NOW}
    case("valid", "valid", "A proof of the issued challenge by a registered key.", [attempt], [ok])
    case(
        "valid_purpose_and_audience_match",
        "valid",
        "The verifier expects this purpose and audience.",
        [{**attempt, "purpose": "tool:call", "audience": SELLER}],
        [ok],
    )
    case(
        "replay_is_refused",
        "invalid",
        "The same proof twice: the nonce is consumed by the first.",
        [attempt, attempt],
        [ok, {"accepted": False, "code": "POP_REPLAYED"}],
    )
    bad = {"proof": {**good, "signature": KEYS["mallory"].signature(jcs(ch), kid=agent.kid)}, "now": NOW}
    case(
        "a_bad_signature_never_consumes_the_nonce",
        "invalid",
        "A forged proof fails, and the genuine one still works after it.",
        [bad, attempt],
        [{"accepted": False, "code": "POP_SIGNATURE_INVALID"}, ok],
    )
    case(
        "nonce_never_issued",
        "invalid",
        "A well-formed challenge the verifier never issued.",
        [attempt],
        [{"accepted": False, "code": "POP_REPLAYED"}],
        challenges=[],
    )
    case(
        "not_yet_valid",
        "invalid",
        "The challenge starts more than the tolerance in the future.",
        [{**attempt, "now": "2026-06-01T11:58:29Z"}],
        [{"accepted": False, "code": "POP_NOT_YET_VALID"}],
    )
    case(
        "valid_at_the_start_with_tolerance",
        "valid",
        "issued_at minus the tolerance is exactly now.",
        [{**attempt, "now": "2026-06-01T11:58:30Z"}],
        [ok],
    )
    case(
        "expired",
        "invalid",
        "now is expires_at plus the tolerance.",
        [{**attempt, "now": "2026-06-01T12:01:30Z"}],
        [{"accepted": False, "code": "POP_EXPIRED"}],
    )
    case(
        "valid_just_before_expiry_with_tolerance",
        "valid",
        "29 s past expires_at is inside the tolerance.",
        [{**attempt, "now": "2026-06-01T12:01:29Z"}],
        [ok],
    )
    case(
        "wrong_purpose",
        "invalid",
        "The verifier wants another purpose.",
        [{**attempt, "purpose": "registration"}],
        [{"accepted": False, "code": "POP_WRONG_PURPOSE"}],
    )
    case(
        "wrong_audience",
        "invalid",
        "The verifier is another audience.",
        [{**attempt, "audience": "urn:other"}],
        [{"accepted": False, "code": "AUDIENCE_MISMATCH"}],
    )
    case(
        "key_not_registered_for_the_subject",
        "invalid",
        "A valid signature by a key nobody registered.",
        [{"proof": proof(ch, KEYS["mallory"]), "now": NOW}],
        [{"accepted": False, "code": "POP_KEY_MISMATCH"}],
    )
    case(
        "key_revoked",
        "invalid",
        "The registered key has been revoked.",
        [attempt],
        [{"accepted": False, "code": "KEY_REVOKED"}],
        trust=trust_config(status={AGENT_URN: "REVOKED"}),
    )
    long_ch = challenge(expires_at="2026-06-01T12:01:01Z")
    case(
        "lifetime_longer_than_allowed",
        "invalid",
        "The challenge lasts 121 s; the limit is 120 s.",
        [{"proof": proof(long_ch, agent), "now": NOW}],
        [{"accepted": False, "code": "SCHEMA_INVALID"}],
        challenges=[long_ch],
    )
    exact = challenge(expires_at="2026-06-01T12:01:00Z", issued_at="2026-06-01T11:59:00Z")
    case(
        "lifetime_exactly_the_limit",
        "valid",
        "A challenge that lasts exactly 120 s.",
        [{"proof": proof(exact, agent), "now": NOW}],
        [ok],
        challenges=[exact],
    )
    case(
        "registration_lifetime_is_300_seconds",
        "valid",
        "With a limit of 300 s a 300 s challenge is accepted.",
        [{"proof": proof(challenge(expires_at="2026-06-01T12:04:00Z"), agent), "now": NOW}],
        [ok],
        challenges=[challenge(expires_at="2026-06-01T12:04:00Z")],
        ttl_seconds=300,
    )
    changed = change(ch, audience="urn:other")
    case(
        "challenge_differs_from_the_one_issued",
        "tamper",
        "The proof signs a challenge with another audience than the issued one.",
        [{"proof": proof(changed, agent), "now": NOW}],
        [{"accepted": False, "code": "SCHEMA_INVALID"}],
    )
    edited = change(ch, purpose="admin")
    case(
        "challenge_changed_after_signing",
        "tamper",
        "The challenge was edited after it was signed.",
        [{"proof": {**good, "challenge": edited}, "now": NOW}],
        [{"accepted": False, "code": "POP_SIGNATURE_INVALID"}],
        challenges=[edited],
    )
    stolen = {**good, "key": KEYS["mallory"].jwk}
    case(
        "proof_presented_with_another_key",
        "tamper",
        "The agent's signature, presented with an attacker's key.",
        [{"proof": stolen, "now": NOW}],
        [{"accepted": False, "code": "POP_KEY_MISMATCH"}],
    )


def keybinding_vectors() -> None:
    agent = KEYS["agent"]
    doc = {
        "schema_version": "1.0",
        "type": "CapabilityCredential",
        "id": "cred-1",
        "issuer": "org:acme",
        "subject": BUYER,
        "issued_at": ISSUED,
        "expires_at": EXPIRES,
    }
    jkt = (
        "sha256:"
        + hashlib.sha256(
            json.dumps({k: agent.jwk[k] for k in ("crv", "kty", "x")}, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    )
    write(
        "keybinding",
        "bind_stamps_the_thumbprint",
        "valid",
        "cnf.jkt is the RFC 7638 thumbprint of the key.",
        {"op": "bind", "document": doc, "key": agent.jwk},
        {"bound": True, "document": {**doc, "cnf": {"jkt": jkt}}},
    )
    p256 = KEYS["acme_p256"]
    write(
        "keybinding",
        "bind_p256",
        "valid",
        "The same for an EC key.",
        {"op": "bind", "document": doc, "key": p256.jwk},
        {"bound": True},
    )
    write(
        "keybinding",
        "bind_refuses_a_signed_document",
        "invalid",
        "The stamp must be inside the signed bytes.",
        {"op": "bind", "document": signed(doc, KEYS["acme"]), "key": agent.jwk},
        {"bound": False, "code": "SCHEMA_INVALID"},
    )
    bound = {**doc, "cnf": {"jkt": jkt}}
    write(
        "keybinding",
        "confirm_matching_key",
        "valid",
        "The proven key is the bound key.",
        {"op": "confirm", "document": bound, "key": agent.jwk},
        {"confirmed": True},
    )
    write(
        "keybinding",
        "confirm_other_key",
        "invalid",
        "A different key proved possession.",
        {"op": "confirm", "document": bound, "key": KEYS["mallory"].jwk},
        {"confirmed": False, "code": "KEY_BINDING_MISMATCH"},
    )
    write(
        "keybinding",
        "confirm_without_a_binding",
        "invalid",
        "The document has no cnf.jkt.",
        {"op": "confirm", "document": doc, "key": agent.jwk},
        {"confirmed": False, "code": "KEY_BINDING_ABSENT"},
    )
    write(
        "keybinding",
        "confirm_binding_changed_to_another_key",
        "tamper",
        "cnf.jkt was replaced by an attacker's thumbprint.",
        {"op": "confirm", "document": {**doc, "cnf": {"jkt": "sha256:" + "0" * 64}}, "key": agent.jwk},
        {"confirmed": False, "code": "KEY_BINDING_MISMATCH"},
    )


# ---- authority epoch -----------------------------------------------------------------------------------------------


def epoch_doc(epoch: int, **members: Any) -> dict[str, Any]:
    base = {
        "schema_version": "1.0",
        "type": "AuthorityEpoch",
        "authority": "org:acme",
        "epoch": epoch,
        "issued_at": "2026-05-30T00:00:00Z",
    }
    return {**base, **members}


def epoch_vectors() -> None:
    acme = KEYS["acme"]

    def doc_case(
        name: str,
        kind: str,
        description: str,
        document: dict[str, Any],
        high: dict[str, int],
        expected: dict[str, Any],
        **more: Any,
    ) -> None:
        write(
            "epoch",
            name,
            kind,
            description,
            {"op": "document", "trust": trust_config(), "document": document, "high_water": high, "now": NOW, **more},
            expected,
        )

    doc_case(
        "newer_epoch_advances_the_mark",
        "valid",
        "Epoch 5 after 3.",
        signed(epoch_doc(5), acme),
        {"org:acme": 3},
        {"accepted": True, "high_water": {"org:acme": 5}},
    )
    doc_case(
        "first_epoch_for_an_authority",
        "valid",
        "No mark yet.",
        signed(epoch_doc(0), acme),
        {},
        {"accepted": True, "high_water": {"org:acme": 0}},
    )
    doc_case(
        "equal_epoch_changes_nothing",
        "valid",
        "Epoch 3 again.",
        signed(epoch_doc(3), acme),
        {"org:acme": 3},
        {"accepted": True, "high_water": {"org:acme": 3}},
    )
    doc_case(
        "older_epoch_is_a_rollback",
        "invalid",
        "Epoch 2 after 3: always refused, the mark stays.",
        signed(epoch_doc(2), acme),
        {"org:acme": 3},
        {"accepted": False, "code": "AUTHORITY_EPOCH_ROLLBACK", "high_water": {"org:acme": 3}},
    )
    doc_case(
        "epoch_raised_after_signing",
        "tamper",
        "The epoch number was raised after signing; the mark must not move.",
        change(signed(epoch_doc(2), acme), epoch=9),
        {"org:acme": 3},
        {"accepted": False, "code": "SIGNATURE_INVALID", "high_water": {"org:acme": 3}},
    )
    doc_case(
        "signed_by_a_key_of_another_authority",
        "invalid",
        "org:other's key signs an epoch of org:acme.",
        signed(epoch_doc(5), KEYS["other"]),
        {},
        {"accepted": False, "code": "ISSUER_MISMATCH", "high_water": {}},
    )
    doc_case(
        "authority_not_trusted",
        "invalid",
        "The authority is not trusted.",
        signed(epoch_doc(5), acme),
        {},
        {"accepted": False, "code": "ISSUER_UNTRUSTED"},
        trust=trust_config(trust=[]),
    )
    doc_case(
        "authority_trusted_only_for_evidence",
        "invalid",
        "Trust for one evidence type does not cover epochs.",
        signed(epoch_doc(5), acme),
        {},
        {"accepted": False, "code": "ISSUER_UNTRUSTED"},
        trust=trust_config(trust=[{"issuer": "org:acme", "evidence_type": "COMPLIANCE"}]),
    )
    doc_case(
        "expired_epoch_document",
        "invalid",
        "Past its optional expiry.",
        signed(epoch_doc(5, expires_at="2026-06-01T11:59:30Z"), acme),
        {},
        {"accepted": False, "code": "CREDENTIAL_EXPIRED"},
    )
    doc_case(
        "issued_in_the_future",
        "invalid",
        "issued_at more than the tolerance ahead.",
        signed(epoch_doc(5, issued_at="2026-06-01T12:01:00Z"), acme),
        {},
        {"accepted": False, "code": "CREDENTIAL_NOT_YET_VALID"},
    )
    doc_case(
        "epoch_is_a_string",
        "invalid",
        "The epoch is an integer.",
        signed({**epoch_doc(5), "epoch": "5"}, acme),
        {},
        {"accepted": False, "code": "SCHEMA_INVALID"},
    )
    for name, kind, high, tolerance, epoch, expected in (
        (
            "older_epoch_is_stale_and_refused",
            "invalid",
            3,
            "reject",
            2,
            {"accepted": False, "code": "AUTHORITY_EPOCH_STALE"},
        ),
        (
            "older_epoch_is_stale_but_allowed_with_a_signal",
            "valid",
            3,
            "allow_with_signal",
            2,
            {"accepted": True, "status": "stale"},
        ),
        ("equal_epoch_is_current", "valid", 3, "reject", 3, {"accepted": True, "status": "current"}),
        ("newer_epoch_is_unconfirmed", "valid", 3, "reject", 9, {"accepted": True, "status": "unconfirmed"}),
        (
            "no_epoch_counts_as_zero_and_is_stale",
            "invalid",
            3,
            "reject",
            None,
            {"accepted": False, "code": "AUTHORITY_EPOCH_STALE"},
        ),
        ("no_epoch_with_no_mark_is_current", "valid", 0, "reject", None, {"accepted": True, "status": "current"}),
    ):
        write(
            "epoch",
            f"credential_{name}",
            kind,
            "A credential's epoch against the mark.",
            {"op": "credential", "epoch": epoch, "high_water": high, "tolerance": tolerance},
            expected,
        )


# ---- W3C Data Integrity --------------------------------------------------------------------------------------------

CTX = ["https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2"]
ALUMNI = {
    "@context": CTX,
    "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
    "type": ["VerifiableCredential", "AlumniCredential"],
    "name": "Alumni Credential",
    "description": "A minimum viable example of an Alumni Credential.",
    "issuer": "https://vc.example/issuers/5678",
    "validFrom": "2023-01-01T00:00:00Z",
    "credentialSubject": {"id": "did:example:abcdefgh", "alumniOf": "The School of Examples"},
}


def with_proof(suite: str, method: str, **more: Any) -> dict[str, Any]:
    return {
        **ALUMNI,
        "proof": {
            "type": "DataIntegrityProof",
            "cryptosuite": suite,
            "created": "2023-02-24T23:36:38Z",
            "verificationMethod": method,
            "proofPurpose": "assertionMethod",
            **more,
        },
    }


def vc_vectors() -> None:
    from cryptography.hazmat.primitives.asymmetric import ec as _ec

    ed_pub = "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2"  # W3C vc-di-eddsa, appendix B.3
    ed_sec = "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq"
    ed_jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64u(interop.base58_decode(ed_pub[1:])[2:])}
    ed_method = f"did:key:{ed_pub}#{ed_pub}"
    ed_value = "z2HnFSSPPBzR36zdDgK8PbEHeXbR56YF24jwMpt3R1eHXQzJDMWS93FCzpvJpwTWd3GAVFuUfjoJdcnTMuVor51aX"
    options = with_proof("eddsa-jcs-2022", ed_method)
    write(
        "vc",
        "w3c_eddsa_jcs_2022_hashes",
        "valid",
        "The published hashes of the W3C eddsa-jcs-2022 example.",
        {"op": "hashes", "document": options},
        {
            "proof_config_hash": "66ab154f5c2890a140cb8388a22a160454f80575f6eae09e5a097cabe539a1db",
            "document_hash": "59b7cb6251b8991add1ce0bc83107e3db9dbbab5bd2c28f687db1a03abc92f19",
        },
    )
    write(
        "vc",
        "w3c_eddsa_jcs_2022_reproduces_the_published_proof_value",
        "valid",
        "Signing with the published secret key gives the published proofValue.",
        {"op": "sign", "document": options, "secret": ed_sec},
        {"proof_value": ed_value},
    )
    published = with_proof("eddsa-jcs-2022", ed_method, proofValue=ed_value)
    write(
        "vc",
        "w3c_eddsa_jcs_2022_published_proof_verifies",
        "valid",
        "The published credential verifies.",
        {"op": "verify", "document": published, "jwk": ed_jwk},
        {"accepted": True},
    )
    ec_pub = "zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP"  # W3C vc-di-ecdsa, appendix A.5 (P-256)
    point = _ec.EllipticCurvePublicKey.from_encoded_point(
        _ec.SECP256R1(), interop.base58_decode(ec_pub[1:])[2:]
    ).public_numbers()
    ec_jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": b64u(point.x.to_bytes(32, "big")),
        "y": b64u(point.y.to_bytes(32, "big")),
    }
    ec_method = f"did:key:{ec_pub}#{ec_pub}"
    ec_value = "z5ptCet75SaEgzG4v4zJhbJtfNi74Wv7Fq15hhKouJQQjEPQvPZKaYxcMXAMLPQS2FXrkCWokNJkFVkwxNzZfD5oT"
    write(
        "vc",
        "w3c_ecdsa_jcs_2019_hashes",
        "valid",
        "The published proof configuration hash of the W3C ecdsa-jcs-2019 example.",
        {"op": "hashes", "document": with_proof("ecdsa-jcs-2019", ec_method)},
        {
            "proof_config_hash": "fe5799489119c7fe3c528715e72bd39d2ec6b4ab345978df32e9a9312648ec25",
            "document_hash": "59b7cb6251b8991add1ce0bc83107e3db9dbbab5bd2c28f687db1a03abc92f19",
        },
    )
    ec_published = with_proof("ecdsa-jcs-2019", ec_method, proofValue=ec_value)
    write(
        "vc",
        "w3c_ecdsa_jcs_2019_published_proof_verifies",
        "valid",
        "The published P-256 credential verifies.",
        {"op": "verify", "document": ec_published, "jwk": ec_jwk},
        {"accepted": True},
    )
    write(
        "vc",
        "w3c_ecdsa_jcs_2019_changed_after_signing",
        "tamper",
        "The published credential with its name changed.",
        {"op": "verify", "document": {**ec_published, "name": "Alumni Credential 2"}, "jwk": ec_jwk},
        {"accepted": False, "code": "SIGNATURE_INVALID"},
    )
    write(
        "vc",
        "w3c_eddsa_jcs_2022_changed_after_signing",
        "tamper",
        "The published credential with its issuer changed.",
        {"op": "verify", "document": {**published, "issuer": "https://vc.example/issuers/9999"}, "jwk": ed_jwk},
        {"accepted": False, "code": "SIGNATURE_INVALID"},
    )
    write(
        "vc",
        "w3c_eddsa_jcs_2022_proof_option_changed",
        "tamper",
        "The `created` time of the proof changed.",
        {
            "op": "verify",
            "document": {**published, "proof": {**published["proof"], "created": "2023-02-25T00:00:00Z"}},
            "jwk": ed_jwk,
        },
        {"accepted": False, "code": "SIGNATURE_INVALID"},
    )
    # our own keys
    ed = KEYS["acme"]
    own = with_proof("eddsa-jcs-2022", "did:example:acme#key-1")
    own_hash = bytes.fromhex(interop.integrity_hashes(own)["hash_data"])
    own_signed = {**own, "proof": {**own["proof"], "proofValue": "z" + interop.base58_encode(ed.sign(own_hash))}}
    write(
        "vc",
        "eddsa_jcs_2022_valid",
        "valid",
        "A proof by another Ed25519 key.",
        {"op": "verify", "document": own_signed, "jwk": ed.jwk},
        {"accepted": True},
    )
    p256 = KEYS["acme_p256"]
    ec_own = with_proof("ecdsa-jcs-2019", "did:example:acme#key-2")
    ec_hash = bytes.fromhex(interop.integrity_hashes(ec_own)["hash_data"])
    ec_signed = {**ec_own, "proof": {**ec_own["proof"], "proofValue": "z" + interop.base58_encode(p256.sign(ec_hash))}}
    write(
        "vc",
        "ecdsa_jcs_2019_valid",
        "valid",
        "A P-256 proof signed here.",
        {"op": "verify", "document": ec_signed, "jwk": p256.jwk},
        {"accepted": True},
    )
    write(
        "vc",
        "ecdsa_suite_with_an_ed25519_key",
        "invalid",
        "The suite says ecdsa-jcs-2019 but the key is Ed25519.",
        {"op": "verify", "document": ec_signed, "jwk": ed.jwk},
        {"accepted": False, "code": "SIGNATURE_INVALID"},
    )
    write(
        "vc",
        "eddsa_suite_with_a_p256_key",
        "invalid",
        "The suite says eddsa-jcs-2022 but the key is P-256.",
        {"op": "verify", "document": own_signed, "jwk": p256.jwk},
        {"accepted": False, "code": "SIGNATURE_INVALID"},
    )
    write(
        "vc",
        "p384_key_is_refused",
        "invalid",
        "Only P-256 is accepted for ecdsa-jcs-2019.",
        {
            "op": "verify",
            "document": ec_signed,
            "jwk": {"kty": "EC", "crv": "P-384", "x": b64u(b"\1" * 48), "y": b64u(b"\2" * 48)},
        },
        {"accepted": False, "code": "SIGNATURE_INVALID"},
    )
    proof = ec_signed["proof"]
    write(
        "vc",
        "proof_value_not_base58btc_multibase",
        "invalid",
        "A proofValue that starts with u (base64url) is refused.",
        {
            "op": "verify",
            "document": {**ec_signed, "proof": {**proof, "proofValue": "u" + proof["proofValue"][1:]}},
            "jwk": p256.jwk,
        },
        {"accepted": False, "code": "SIGNATURE_INVALID"},
    )
    write(
        "vc",
        "proof_value_with_a_character_outside_the_alphabet",
        "invalid",
        "0 is not in the base58btc alphabet.",
        {
            "op": "verify",
            "document": {**ec_signed, "proof": {**proof, "proofValue": "z0" + proof["proofValue"][2:]}},
            "jwk": p256.jwk,
        },
        {"accepted": False, "code": "SIGNATURE_INVALID"},
    )
    write(
        "vc",
        "proof_array_is_refused",
        "invalid",
        "A proof must be a single object in Phase 1b.",
        {"op": "verify", "document": {**ec_signed, "proof": [proof]}, "jwk": p256.jwk},
        {"accepted": False, "code": "SCHEMA_INVALID"},
    )
    write(
        "vc",
        "proof_purpose_authentication",
        "invalid",
        "proofPurpose must be assertionMethod.",
        {
            "op": "verify",
            "document": {**ec_signed, "proof": {**proof, "proofPurpose": "authentication"}},
            "jwk": p256.jwk,
        },
        {"accepted": False, "code": "SCHEMA_INVALID"},
    )
    write(
        "vc",
        "proof_type_not_data_integrity",
        "invalid",
        "type must be DataIntegrityProof.",
        {
            "op": "verify",
            "document": {**ec_signed, "proof": {**proof, "type": "Ed25519Signature2020"}},
            "jwk": p256.jwk,
        },
        {"accepted": False, "code": "SCHEMA_INVALID"},
    )
    write(
        "vc",
        "unknown_cryptosuite",
        "invalid",
        "ecdsa-rdfc-2019 is not accepted.",
        {
            "op": "verify",
            "document": {**ec_signed, "proof": {**proof, "cryptosuite": "ecdsa-rdfc-2019"}},
            "jwk": p256.jwk,
        },
        {"accepted": False, "code": "UNSUPPORTED_ALGORITHM"},
    )
    write(
        "vc",
        "signature_of_the_wrong_length",
        "invalid",
        "A proofValue that decodes to 63 bytes.",
        {
            "op": "verify",
            "document": {**ec_signed, "proof": {**proof, "proofValue": "z" + interop.base58_encode(b"\1" * 63)}},
            "jwk": p256.jwk,
        },
        {"accepted": False, "code": "SIGNATURE_INVALID"},
    )


# ---- SD-JWT --------------------------------------------------------------------------------------------------------


def disclosure(salt: str, name: str, value: Any) -> str:
    return b64u(
        json.dumps([salt, name, value]).encode()
    )  # json.dumps puts a space after each comma, as in the SD-JWT RFC


def sdjwt_vectors() -> None:
    ed = KEYS["acme"]
    d_given = disclosure("2GLC42sKQveCfGfryNRN9w", "given_name", "John")
    d_family = disclosure("eluV5Og3gSNII8EYnsxA_A", "family_name", "Doe")
    d_email = disclosure("6Ij7tM-a5iVPGboS5tmvVA", "email", "johndoe@example.com")
    digest = interop.sd_digest
    claims = {
        "iss": "org:acme",
        "iat": NOW_EPOCH - 60,
        "exp": NOW_EPOCH + 3600,
        "sub": "user-1",
        "_sd_alg": "sha-256",
        "_sd": sorted([digest(d_given), digest(d_family), digest(d_email)]),
    }
    jwt = compact({"alg": "EdDSA", "kid": ed.kid, "typ": "dc+sd-jwt"}, claims, ed)
    ctx = {"keys": [ed.jwk], "now": NOW_EPOCH}
    write(
        "sdjwt",
        "digest_of_the_rfc_example_disclosure",
        "valid",
        "The digest is over the ASCII bytes of the disclosure string, as in the SD-JWT RFC, never over a canonical "
        "form.",
        {"op": "digest", "disclosure": "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd"},
        {"digest": "jsu9yVulwQQlhFlM_3JlzMaSFzglhQG0DpfayQwLUK4"},
    )
    write(
        "sdjwt",
        "digest_is_not_a_canonical_json_digest",
        "valid",
        "The same claim with different spacing is a different disclosure string and so a different digest.",
        {"op": "digest", "disclosure": b64u(b'["2GLC42sKQveCfGfryNRN9w","given_name","John"]')},
        {"digest": digest(b64u(b'["2GLC42sKQveCfGfryNRN9w","given_name","John"]'))},
    )
    write(
        "sdjwt",
        "valid_two_of_three_disclosed",
        "valid",
        "An undisclosed claim is absent, and that is not a failure.",
        {"op": "verify", "presentation": f"{jwt}~{d_given}~{d_family}~", **ctx},
        {"accepted": True, "claims": {"given_name": "John", "family_name": "Doe", "sub": "user-1"}},
    )
    write(
        "sdjwt",
        "valid_nothing_disclosed",
        "valid",
        "No disclosure at all.",
        {"op": "verify", "presentation": f"{jwt}~", **ctx},
        {"accepted": True, "claims": {"sub": "user-1"}},
    )
    swapped = disclosure("2GLC42sKQveCfGfryNRN9w", "given_name", "Jane")
    write(
        "sdjwt",
        "disclosure_value_changed",
        "tamper",
        "A disclosed value was edited: its digest is not in the signed list.",
        {"op": "verify", "presentation": f"{jwt}~{swapped}~", **ctx},
        {"accepted": False, "code": "SIGNATURE_INVALID"},
    )
    extra = disclosure("0000000000000000000000", "admin", True)
    write(
        "sdjwt",
        "disclosure_the_issuer_never_signed_for",
        "invalid",
        "A disclosure of a claim the issuer did not commit to.",
        {"op": "verify", "presentation": f"{jwt}~{extra}~", **ctx},
        {"accepted": False, "code": "SIGNATURE_INVALID"},
    )
    write(
        "sdjwt",
        "disclosure_twice",
        "invalid",
        "The same disclosure presented twice.",
        {"op": "verify", "presentation": f"{jwt}~{d_given}~{d_given}~", **ctx},
        {"accepted": False, "code": "SCHEMA_INVALID"},
    )
    clash_claims = {**claims, "given_name": "Plain", "_sd": [digest(d_given)]}
    write(
        "sdjwt",
        "disclosed_name_collides_with_a_plain_claim",
        "invalid",
        "A disclosure may not redefine a claim in the clear.",
        {
            "op": "verify",
            "presentation": f"{compact({'alg': 'EdDSA', 'kid': ed.kid}, clash_claims, ed)}~{d_given}~",
            **ctx,
        },
        {"accepted": False, "code": "SCHEMA_INVALID"},
    )
    write(
        "sdjwt",
        "digest_algorithm_other_than_sha_256",
        "invalid",
        "Only sha-256 is accepted.",
        {
            "op": "verify",
            "presentation": f"{compact({'alg': 'EdDSA', 'kid': ed.kid}, {**claims, '_sd_alg': 'sha-512'}, ed)}~",
            **ctx,
        },
        {"accepted": False, "code": "UNSUPPORTED_ALGORITHM"},
    )
    write(
        "sdjwt",
        "presentation_with_a_key_binding_jwt",
        "invalid",
        "A trailing key-binding JWT is not supported in 1b vectors.",
        {"op": "verify", "presentation": f"{jwt}~{d_given}~{jwt}", **ctx},
        {"accepted": False, "code": "SCHEMA_INVALID"},
    )
    write(
        "sdjwt",
        "issuer_jwt_expired",
        "invalid",
        "The issuer JWT is past exp.",
        {
            "op": "verify",
            "presentation": f"{compact({'alg': 'EdDSA', 'kid': ed.kid}, {**claims, 'exp': NOW_EPOCH - 30}, ed)}~",
            **ctx,
        },
        {"accepted": False, "code": "CREDENTIAL_EXPIRED"},
    )
    h, _, s = jwt.split(".")
    forged = b64u(json.dumps({**claims, "sub": "user-2"}, sort_keys=True, separators=(",", ":")).encode())
    write(
        "sdjwt",
        "issuer_payload_changed",
        "tamper",
        "The signed payload was changed.",
        {"op": "verify", "presentation": f"{h}.{forged}.{s}~", **ctx},
        {"accepted": False, "code": "SIGNATURE_INVALID"},
    )
    write(
        "sdjwt",
        "disclosure_not_base64url",
        "invalid",
        "A disclosure that is not strict base64url.",
        {"op": "verify", "presentation": f"{jwt}~{d_given}==~", **ctx},
        {"accepted": False, "code": "SCHEMA_INVALID"},
    )
    write(
        "sdjwt",
        "disclosure_is_not_json",
        "invalid",
        "A disclosure that is valid base64url but not JSON.",
        {"op": "verify", "presentation": f"{jwt}~{b64u(b'not json')}~", **ctx},
        {"accepted": False, "code": "SCHEMA_INVALID"},
    )
    write(
        "sdjwt",
        "disclosure_is_not_a_three_element_array",
        "invalid",
        "A disclosure must be [salt, name, value].",
        {"op": "verify", "presentation": f"{jwt}~{b64u(b'[1,2]')}~", **ctx},
        {"accepted": False, "code": "SCHEMA_INVALID"},
    )


BUILDERS = (
    thumbprint_vectors,
    crypto_vectors,
    jws_vectors,
    credential_vectors,
    delegation_vectors,
    delegation_bound_vectors,
    evidence_vectors,
    passport_vectors,
    pop_vectors,
    keybinding_vectors,
    epoch_vectors,
    vc_vectors,
    sdjwt_vectors,
)


def render(vector: dict[str, Any]) -> str:
    return json.dumps(vector, indent=2, ensure_ascii=False, sort_keys=True) + "\n"


def build_all() -> dict[str, str]:
    """Every vector as the text of its file. Each one is checked against the reference checker as it is built."""
    written.clear()
    for build in BUILDERS:
        build()
    return {vector_id: render(vector) for vector_id, vector in sorted(written.items())}


def main() -> int:
    if "--check" not in sys.argv:
        texts = build_all()
        for vector_id, text in texts.items():
            path = ROOT / f"{vector_id}.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8", newline="\n")
        print(f"wrote {len(texts)} trust vectors")
        return 0
    # ML-DSA signs with fresh randomness: a vector that differs between two runs is not comparable, every other is
    first, second = build_all(), build_all()
    stable = [vector_id for vector_id in first if first[vector_id] == second[vector_id]]
    differences = []
    for vector_id in stable:
        path = ROOT / f"{vector_id}.json"
        if not path.exists() or path.read_text("utf-8") != first[vector_id]:
            differences.append(vector_id)
    for vector_id in differences:
        print(f"differs from the committed file: {vector_id}", file=sys.stderr)
    print(f"compared {len(stable)} of {len(first)} vectors; the others are signed with ML-DSA", file=sys.stderr)
    return 1 if differences else 0


if __name__ == "__main__":
    sys.exit(main())
