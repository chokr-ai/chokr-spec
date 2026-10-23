"""Keys and signature algorithms of the trust vectors (A6.6): JWK thumbprints and raw signature verification.

The closed list of algorithms is Ed25519, ES256 (the 64-byte `R || S` form, not DER), RS256 (2048 bits or more,
exponent 65537) and ML-DSA-44, ML-DSA-65 and ML-DSA-87. Verification pins the algorithm of the **key**; the algorithm
a signature claims for itself is only compared with it, so a signature can never choose how it is checked.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from chokr_spec.signatures import Rejected, b64url_decode

try:  # post-quantum signatures need cryptography 48 or later
    from cryptography.hazmat.primitives.asymmetric import mldsa

    _MLDSA: dict[str, Any] = {
        "ML-DSA-44": mldsa.MLDSA44PublicKey,
        "ML-DSA-65": mldsa.MLDSA65PublicKey,
        "ML-DSA-87": mldsa.MLDSA87PublicKey,
    }
except ImportError:  # pragma: no cover - the pinned minimum has it
    _MLDSA = {}

ALGORITHMS = ("Ed25519", "ES256", "RS256", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87")
_NAMES = {"Ed25519": "Ed25519", "EdDSA": "Ed25519", **{name: name for name in ALGORITHMS}}
_THUMBPRINT_MEMBERS = {
    "OKP": ("crv", "kty", "x"),
    "EC": ("crv", "kty", "x", "y"),
    "RSA": ("e", "kty", "n"),
    "AKP": ("alg", "kty", "pub"),
}
RSA_MIN_BITS = 2048
RSA_EXPONENT = 65537


def normalize_alg(name: object) -> str | None:
    """The name of an algorithm in the closed list (`EdDSA` is Ed25519 on the wire), or `None` for anything else."""
    return _NAMES.get(name) if isinstance(name, str) else None


def jwk_alg(jwk: Mapping[str, Any]) -> str | None:
    """The algorithm a key is bound to: its `alg`, or the one its type implies."""
    if "alg" in jwk:
        return normalize_alg(jwk["alg"])
    kind = (str(jwk.get("kty")), str(jwk.get("crv")))
    implied = {("OKP", "Ed25519"): "Ed25519", ("EC", "P-256"): "ES256"}.get(kind)
    return implied or ("RS256" if jwk.get("kty") == "RSA" else None)


def thumbprint_input(jwk: Mapping[str, Any]) -> bytes:
    """The RFC 7638 input: the required members of the key type, sorted, with no whitespace."""
    members = _THUMBPRINT_MEMBERS.get(str(jwk.get("kty")))
    if members is None or any(not isinstance(jwk.get(m), str) for m in members):
        raise ValueError("not a public key of a known type")
    return json.dumps({m: jwk[m] for m in members}, sort_keys=True, separators=(",", ":")).encode("ascii")


def thumbprint(jwk: Mapping[str, Any]) -> str:
    """`sha256:` and the lower-case hex of the RFC 7638 thumbprint. This is the `cnf.jkt` value."""
    return "sha256:" + hashlib.sha256(thumbprint_input(jwk)).hexdigest()


def key_urn(jwk: Mapping[str, Any]) -> str:
    """The self-certifying id of a key: `urn:chokr:key:sha256:` and the hex of its thumbprint."""
    return "urn:chokr:key:sha256:" + thumbprint(jwk).removeprefix("sha256:")


def _int(text: object) -> int:
    return int.from_bytes(b64url_decode(str(text)), "big")


def _ed25519(jwk: Mapping[str, Any], message: bytes, signature: bytes) -> None:
    Ed25519PublicKey.from_public_bytes(b64url_decode(str(jwk["x"]))).verify(signature, message)


def _es256(jwk: Mapping[str, Any], message: bytes, signature: bytes) -> None:
    if len(signature) != 64:  # a DER signature, or any other length, is not the JWS form
        raise InvalidSignature
    point = ec.EllipticCurvePublicNumbers(_int(jwk["x"]), _int(jwk["y"]), ec.SECP256R1())
    der = encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
    point.public_key().verify(der, message, ec.ECDSA(hashes.SHA256()))


def _rs256(jwk: Mapping[str, Any], message: bytes, signature: bytes) -> None:
    n, e = _int(jwk["n"]), _int(jwk["e"])
    if n.bit_length() < RSA_MIN_BITS or e != RSA_EXPONENT:
        raise Rejected("UNSUPPORTED_ALGORITHM")
    rsa.RSAPublicNumbers(e, n).public_key().verify(signature, message, padding.PKCS1v15(), hashes.SHA256())


def _mldsa(alg: str) -> Callable[[Mapping[str, Any], bytes, bytes], None]:
    def verify(jwk: Mapping[str, Any], message: bytes, signature: bytes) -> None:
        _MLDSA[alg].from_public_bytes(b64url_decode(str(jwk["pub"]))).verify(signature, message)

    return verify


def verify_raw(jwk: Mapping[str, Any], message: bytes, signature: bytes) -> None:
    """Return normally only when `signature` verifies over `message` with the algorithm the key is bound to.

    Raises `Rejected("UNSUPPORTED_ALGORITHM")` for an algorithm or key this checker does not accept (an RSA key under
    2048 bits, a curve other than P-256, a post-quantum key without library support) and `Rejected("SIGNATURE_INVALID")`
    for a signature that does not verify.
    """
    alg = jwk_alg(jwk)
    verifiers: dict[str, Callable[[Mapping[str, Any], bytes, bytes], None]] = {
        "Ed25519": _ed25519,
        "ES256": _es256,
        "RS256": _rs256,
        **{name: _mldsa(name) for name in _MLDSA},
    }
    expected_kty = {"Ed25519": "OKP", "ES256": "EC", "RS256": "RSA"}.get(alg or "", "AKP")
    curve_ok = {"Ed25519": "Ed25519", "ES256": "P-256"}.get(alg or "")
    if (
        alg is None
        or alg not in verifiers
        or jwk.get("kty") != expected_kty
        or (curve_ok is not None and jwk.get("crv") != curve_ok)
    ):
        raise Rejected("UNSUPPORTED_ALGORITHM")
    try:
        verifiers[alg](jwk, message, signature)
    except Rejected:
        raise
    except (InvalidSignature, ValueError, KeyError, TypeError) as exc:
        raise Rejected("SIGNATURE_INVALID") from exc
