"""The formats trust borrows from others: compact JWS (CHK-TRU-02), W3C Data Integrity proofs (CHK-ADP-09) and SD-JWT
disclosures (CHK-ADP-10). Each function raises `Rejected(code)` for input it refuses and returns the verified facts."""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from chokr_spec.canonical import canonicalize
from chokr_spec.keys import jwk_alg, verify_raw
from chokr_spec.signatures import Rejected, b64url_decode
from chokr_spec.trust import DEFAULT_SKEW

JOSE_NAME = {"Ed25519": "EdDSA"}  # the one algorithm whose JOSE name differs from ours
FORBIDDEN_HEADERS = frozenset({"jku", "jwk", "x5u", "x5c", "crit"})
SUITES = {"eddsa-jcs-2022": "Ed25519", "ecdsa-jcs-2019": "ES256"}
BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


# ---- compact JWS ---------------------------------------------------------------------------------------------------


def _segment(text: str) -> bytes:
    try:
        return b64url_decode(text)
    except ValueError as exc:
        raise Rejected("SCHEMA_INVALID") from exc


def _json_object(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except ValueError as exc:
        raise Rejected("SCHEMA_INVALID") from exc
    if not isinstance(value, dict):
        raise Rejected("SCHEMA_INVALID")
    return value


def verify_compact(
    token: str, keys: Sequence[Mapping[str, Any]], *, now: int, skew: int = DEFAULT_SKEW
) -> dict[str, Any]:
    """Verify a compact JWS and return its claims. The key is only ever one of `keys`, chosen by `kid` (or the single
    key when there is no `kid`); the header `alg` must be the name of the algorithm that key is bound to. The signature
    is checked over the received segments, never over a re-serialized form. `now` is whole seconds since the epoch."""
    parts = token.split(".")
    if len(parts) != 3 or not all(parts):
        raise Rejected("SCHEMA_INVALID")
    header = _json_object(_segment(parts[0]))
    claims = _json_object(_segment(parts[1]))
    signature = _segment(parts[2])
    if FORBIDDEN_HEADERS & header.keys():
        raise Rejected("SCHEMA_INVALID")
    kid = header.get("kid")
    chosen = [k for k in keys if k.get("kid") == kid] if kid is not None else list(keys) if len(keys) == 1 else []
    if len(chosen) != 1:
        raise Rejected("JWS_KID_UNKNOWN")
    bound = jwk_alg(chosen[0])
    if header.get("alg") != JOSE_NAME.get(bound or "", bound):
        raise Rejected("JWS_ALG_MISMATCH")
    verify_raw(chosen[0], f"{parts[0]}.{parts[1]}".encode("ascii"), signature)
    exp, nbf = claims.get("exp"), claims.get("nbf")
    if isinstance(exp, int | float) and now >= exp + skew:
        raise Rejected("CREDENTIAL_EXPIRED")
    if isinstance(nbf, int | float) and now < nbf - skew:
        raise Rejected("CREDENTIAL_NOT_YET_VALID")
    return claims


# ---- base58btc and multibase ---------------------------------------------------------------------------------------


def base58_encode(data: bytes) -> str:
    """Base58 with the Bitcoin alphabet."""
    number = int.from_bytes(data, "big")
    out = ""
    while number:
        number, rest = divmod(number, 58)
        out = BASE58[rest] + out
    return BASE58[0] * (len(data) - len(data.lstrip(b"\0"))) + out


def base58_decode(text: str) -> bytes:
    """Decode base58btc text. A character outside the alphabet raises `ValueError`."""
    number = 0
    for char in text:
        number = number * 58 + BASE58.index(char)
    body = number.to_bytes((number.bit_length() + 7) // 8, "big")
    return b"\0" * (len(text) - len(text.lstrip(BASE58[0]))) + body


# ---- W3C Data Integrity (eddsa-jcs-2022, ecdsa-jcs-2019) -----------------------------------------------------------


def _sha256(value: Any) -> bytes:
    return hashlib.sha256(canonicalize(value)).digest()


def integrity_hashes(document: Mapping[str, Any]) -> dict[str, str]:
    """The proof configuration hash, the document hash and their concatenation, as hex. The proof configuration is the
    proof without `proofValue` and with the document's `@context`."""
    proof = document["proof"]
    config = {k: v for k, v in proof.items() if k != "proofValue"}
    if "@context" in document:
        config["@context"] = document["@context"]
    unsecured = {k: v for k, v in document.items() if k != "proof"}
    config_hash, document_hash = _sha256(config), _sha256(unsecured)
    return {
        "proof_config_hash": config_hash.hex(),
        "document_hash": document_hash.hex(),
        "hash_data": (config_hash + document_hash).hex(),
    }


def verify_integrity(document: Mapping[str, Any], jwk: Mapping[str, Any]) -> None:
    """Verify one `DataIntegrityProof`. `jwk` is the key the verification method resolves to. Failures close: a
    suite whose key is of another kind or curve is `SIGNATURE_INVALID`, not an error that escapes."""
    proof = document.get("proof")
    if not isinstance(proof, dict):  # an array of proofs is not accepted in Phase 1b
        raise Rejected("SCHEMA_INVALID")
    if proof.get("type") != "DataIntegrityProof" or proof.get("proofPurpose") != "assertionMethod":
        raise Rejected("SCHEMA_INVALID")
    suite = proof.get("cryptosuite")
    if suite not in SUITES:
        raise Rejected("UNSUPPORTED_ALGORITHM")
    value = proof.get("proofValue")
    if not isinstance(value, str) or not value.startswith("z"):
        raise Rejected("SIGNATURE_INVALID")
    if jwk_alg(jwk) != SUITES[suite] or (suite == "ecdsa-jcs-2019" and jwk.get("crv") != "P-256"):
        raise Rejected("SIGNATURE_INVALID")
    try:
        signature = base58_decode(value[1:])
    except ValueError as exc:
        raise Rejected("SIGNATURE_INVALID") from exc
    verify_raw(jwk, bytes.fromhex(integrity_hashes(document)["hash_data"]), signature)


def sign_integrity_eddsa(document: Mapping[str, Any], secret_multibase: str) -> str:
    """The `proofValue` of `eddsa-jcs-2022` for a document that carries its proof options. The secret is a multibase
    base58btc Ed25519 key with the `0x8026` multicodec prefix."""
    raw = base58_decode(secret_multibase.removeprefix("z"))
    if raw[:2] != b"\x80\x26" or len(raw) != 34:
        raise ValueError("not an Ed25519 secret key")
    key = Ed25519PrivateKey.from_private_bytes(raw[2:])
    data = bytes.fromhex(integrity_hashes(document)["hash_data"])
    return "z" + base58_encode(key.sign(data))


# ---- SD-JWT --------------------------------------------------------------------------------------------------------


def sd_digest(disclosure: str) -> str:
    """The digest of a disclosure: unpadded base64url of SHA-256 over the ASCII bytes of the disclosure string, as the
    SD-JWT specification defines it. It is never computed over a canonical form."""
    return base64.urlsafe_b64encode(hashlib.sha256(disclosure.encode("ascii")).digest()).rstrip(b"=").decode("ascii")


def verify_sd_jwt(
    presentation: str, keys: Sequence[Mapping[str, Any]], *, now: int, skew: int = DEFAULT_SKEW
) -> dict[str, Any]:
    """Verify the issuer signature, then check that every disclosure was committed to in the signed `_sd` list.
    A claim that is not disclosed is simply absent from the result: that is not a failure. Returns the claims."""
    parts = presentation.split("~")
    if len(parts) < 2 or parts[-1] != "":  # a presentation ends with `~` (no key-binding JWT in these vectors)
        raise Rejected("SCHEMA_INVALID")
    claims = verify_compact(parts[0], keys, now=now, skew=skew)
    if claims.get("_sd_alg", "sha-256") != "sha-256":
        raise Rejected("UNSUPPORTED_ALGORITHM")
    committed = claims.get("_sd", [])
    if not isinstance(committed, list) or len(set(committed)) != len(committed):
        raise Rejected("SCHEMA_INVALID")
    result = {k: v for k, v in claims.items() if k not in ("_sd", "_sd_alg")}
    seen: set[str] = set()
    for disclosure in parts[1:-1]:
        try:
            decoded = json.loads(_segment(disclosure))
        except Rejected:
            raise
        except ValueError as exc:
            raise Rejected("SCHEMA_INVALID") from exc
        if not (isinstance(decoded, list) and len(decoded) == 3 and isinstance(decoded[1], str)):
            raise Rejected("SCHEMA_INVALID")
        digest = sd_digest(disclosure)
        if digest not in committed:
            raise Rejected("SIGNATURE_INVALID")  # a disclosure the issuer never signed for
        if digest in seen or decoded[1] in result or decoded[1] in ("_sd", "..."):
            raise Rejected("SCHEMA_INVALID")
        seen.add(digest)
        result[decoded[1]] = decoded[2]
    return result
