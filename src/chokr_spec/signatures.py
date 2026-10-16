"""Offline verification of a signed document against the published keys of its signer.

A document carries `signature: {alg, kid, value}`. The checks run in this order, and the order decides which code a
bad document gets:

1. A document without `signature` is rejected as `VERDICT_UNSIGNED`.
2. A `signature` that is not an object with text `alg`, `kid` and `value` is `SIGNATURE_INVALID`.
3. A `kid` outside the allowed set is `KID_NOT_ALLOWED`, even when no key has that `kid`.
4. A `kid` that is not among the keys is `UNKNOWN_KID`.
5. The algorithm of the key is the only one used. A `signature.alg` that differs, or is `none`, is `SIGNATURE_INVALID`.
   A key type this checker cannot verify is `UNSUPPORTED_ALGORITHM`.
6. The signature must be strict unpadded base64url and verify over the canonical JSON of the document without
   `signature`. Anything else is `SIGNATURE_INVALID`.

This checker verifies Ed25519 (`EdDSA`).
"""

from __future__ import annotations

import base64
import re
from collections.abc import Collection, Mapping
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from chokr_spec.canonical import canonicalize
from chokr_spec.errors import CanonicalizationError

EDDSA = "EdDSA"
_ED_NAMES = frozenset({"EdDSA", "Ed25519"})
_B64URL = re.compile(r"[A-Za-z0-9_-]*")


class Rejected(Exception):
    """A document that must not be acted on. `code` says why. The message never carries the document."""

    def __init__(self, code: str, kid: str | None = None) -> None:
        super().__init__(code)
        self.code, self.kid = code, kid


def b64url_decode(text: str) -> bytes:
    """Decode strict unpadded base64url text.

    Only the characters `A-Z a-z 0-9 - _` are accepted. Padding, whitespace, the standard alphabet and non-zero bits
    after the last full byte are all refused, so every byte string has exactly one accepted text.
    """
    if not isinstance(text, str) or _B64URL.fullmatch(text) is None or len(text) % 4 == 1:
        raise ValueError("not base64url")
    data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if b64url_encode(data) != text:
        raise ValueError("not canonical base64url")
    return data


def b64url_encode(data: bytes) -> str:
    """Encode bytes as unpadded base64url text."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def verify_document(
    document: Mapping[str, Any],
    keys: Mapping[str, Mapping[str, Any]],
    allowed: Collection[str] | None,
    *,
    require_signature: bool = True,
) -> None:
    """Return normally only for a document whose signature verifies. Anything else raises `Rejected`.

    `keys` maps each `kid` to a JWK. `allowed` is the set of kids that may sign, or `None` to allow every key.
    """
    signature = document.get("signature")
    if signature is None:
        if require_signature:
            raise Rejected("VERDICT_UNSIGNED")
        return
    if not isinstance(signature, Mapping):
        raise Rejected("SIGNATURE_INVALID")
    alg, kid, value = signature.get("alg"), signature.get("kid"), signature.get("value")
    if not (isinstance(alg, str) and isinstance(kid, str) and isinstance(value, str)):
        raise Rejected("SIGNATURE_INVALID")
    if allowed is not None and kid not in allowed:
        raise Rejected("KID_NOT_ALLOWED", kid)
    jwk = keys.get(kid)
    if jwk is None:
        raise Rejected("UNKNOWN_KID", kid)
    key_alg = jwk.get("alg") or (EDDSA if jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519" else None)
    if alg.lower() == "none" or key_alg is None:
        raise Rejected("SIGNATURE_INVALID", kid)
    if key_alg not in _ED_NAMES or jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise Rejected("UNSUPPORTED_ALGORITHM", kid)
    if alg not in _ED_NAMES:
        raise Rejected("SIGNATURE_INVALID", kid)
    try:
        public = Ed25519PublicKey.from_public_bytes(b64url_decode(str(jwk.get("x"))))
        message = canonicalize({k: v for k, v in document.items() if k != "signature"})
        public.verify(b64url_decode(value), message)
    except (InvalidSignature, ValueError, CanonicalizationError, TypeError) as exc:
        raise Rejected("SIGNATURE_INVALID", kid) from exc
