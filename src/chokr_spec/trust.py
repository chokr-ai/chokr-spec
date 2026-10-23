"""The trust checks of the vectors: what the reference checker accepts, and the stable
error code of the first check that fails.

Every function raises `Rejected(code)` for a document it refuses and returns the verified facts otherwise. The order
of the checks is the order the specification states, so two implementations that disagree on a vector disagree on the
check that fires first. Time is always an argument (`now`), never read from a clock, and one tolerance applies to every
time check (`clock_skew_seconds`, default 30, at most 300).

Where the specification names no code for a step, the checker uses the one in the closest rule and the vector pins it.
"""

from __future__ import annotations

import hashlib
import hmac
import itertools
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from functools import cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from chokr_spec.canonical import canonicalize
from chokr_spec.keys import jwk_alg, key_urn, normalize_alg, thumbprint, verify_raw
from chokr_spec.signatures import Rejected, b64url_decode

DEFAULT_SKEW = 30
MAX_SKEW = 300
DEFAULT_MAX_CHAIN_DEPTH = 32
DEFAULT_POP_TTL = 120
KEY_ID_PREFIX = "urn:chokr:key:sha256:"
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z")
_NATIVE_ID = re.compile(r"urn:chokr:org:([^:]+):agent:([^:]+)")
_SIGNATURE_MEMBERS = ("signature", "proofs")


# ---- schemas, time, store ------------------------------------------------------------------------------------------


@cache
def _validator(schemas: Path, name: str) -> Draft202012Validator:
    return Draft202012Validator(json.loads((schemas / f"{name}.schema.json").read_text("utf-8")))


def require_schema(schemas: Path, name: str, document: object) -> None:
    """Raise `SCHEMA_INVALID` unless `document` is valid under the named schema."""
    if not _validator(schemas, name).is_valid(document):
        raise Rejected("SCHEMA_INVALID")


def parse_time(text: object) -> datetime:
    """An RFC 3339 UTC timestamp with `Z`. Any other form is `SCHEMA_INVALID`."""
    if not isinstance(text, str) or _TIMESTAMP.fullmatch(text) is None:
        raise Rejected("SCHEMA_INVALID")
    return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(UTC)


def check_skew(skew: object) -> int:
    """The clock tolerance in seconds: an integer from 0 to 300, else `SCHEMA_INVALID`."""
    if isinstance(skew, bool) or not isinstance(skew, int) or not 0 <= skew <= MAX_SKEW:
        raise Rejected("SCHEMA_INVALID")
    return skew


def check_window(issued_at: datetime, expires_at: datetime | None, now: datetime, skew: int) -> None:
    """A document is valid on `issued_at - skew <= now < expires_at + skew`."""
    tolerance = timedelta(seconds=skew)
    if now < issued_at - tolerance:
        raise Rejected("CREDENTIAL_NOT_YET_VALID")
    if expires_at is not None and now >= expires_at + tolerance:
        raise Rejected("CREDENTIAL_EXPIRED")


@dataclass
class TrustStore:
    """The keys of issuers, what each issuer is trusted for, and the status of ids (a `trust_config` document)."""

    keys: dict[str, dict[str, Mapping[str, Any]]] = field(default_factory=dict)
    owner: dict[str, str] = field(default_factory=dict)
    relationships: list[Mapping[str, Any]] = field(default_factory=list)
    status: dict[str, str] = field(default_factory=dict)

    @classmethod
    def load(cls, config: Mapping[str, Any], schemas: Path) -> TrustStore:
        """Build the store from a `trust_config` document. A `kid` cannot be rebound to another issuer."""
        require_schema(schemas, "trust_config", config)
        store = cls(relationships=list(config["trust"]), status=dict(config.get("status", {})))
        for entry in config["issuer_keys"]:
            issuer, jwk = entry["issuer"], entry["key"]
            if store.owner.setdefault(jwk["kid"], issuer) != issuer:
                raise Rejected("SCHEMA_INVALID")
            store.keys.setdefault(issuer, {})[jwk["kid"]] = jwk
        return store

    def trusted(self, issuer: str, evidence_type: str = "*") -> Mapping[str, Any] | None:
        """The relationship that trusts `issuer` for `evidence_type`, if any. `*` in a relationship matches every
        type; a query for `*` (a credential, a delegation, an epoch) is matched only by a `*` relationship."""
        for relationship in self.relationships:
            kind = relationship.get("evidence_type", "*")
            if relationship["issuer"] == issuer and kind in ("*", evidence_type):
                return relationship
        return None

    def active(self, *ids: str) -> bool:
        """True when none of the ids is `REVOKED` or `SUSPENDED`. An unknown id is active."""
        return all(self.status.get(i, "ACTIVE") == "ACTIVE" for i in ids)


def _signed_part(document: Mapping[str, Any]) -> bytes:
    return canonicalize({k: v for k, v in document.items() if k not in _SIGNATURE_MEMBERS})


def _signatures(document: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    if isinstance(document.get("signature"), Mapping):
        return [document["signature"]]
    proofs = document.get("proofs")
    if isinstance(proofs, list) and proofs:
        return list(proofs)
    raise Rejected("SCHEMA_INVALID")


def check_signature(jwk: Mapping[str, Any], signature: Mapping[str, Any], message: bytes) -> None:
    """One detached signature against one key, pinned to the key's algorithm."""
    if normalize_alg(signature.get("alg")) != jwk_alg(jwk):  # a different or unknown name, `none` included
        raise Rejected("SIGNATURE_INVALID")
    try:
        raw = b64url_decode(str(signature.get("value")))
    except ValueError as exc:
        raise Rejected("SIGNATURE_INVALID") from exc
    verify_raw(jwk, message, raw)


def verify_signed(
    document: Mapping[str, Any],
    store: TrustStore,
    issuer: str,
    *,
    embedded: Mapping[str, Mapping[str, Any]] | None = None,
) -> None:
    """The first steps of every signed document: the key belongs to the issuer, every signature verifies, no key of
    the document has been revoked. `embedded` maps kids to keys for the self-verifying delegation path."""
    message, keys_used = _signed_part(document), []
    for signature in _signatures(document):
        kid = str(signature.get("kid"))
        if embedded is not None:
            jwk = embedded.get(kid)
            if jwk is None:
                raise Rejected("KEY_NOT_FOUND")
        else:
            owner = store.owner.get(kid)
            if owner is None:
                raise Rejected("KEY_NOT_FOUND")
            if owner != issuer:
                raise Rejected("ISSUER_MISMATCH")
            jwk = store.keys[issuer][kid]
        check_signature(jwk, signature, message)
        keys_used.append(jwk)
    if not store.active(*(key_urn(k) for k in keys_used)):
        raise Rejected("KEY_REVOKED")


# ---- credential ----------------------------------------------------------------------------------------------------


def verify_credential(
    document: Mapping[str, Any],
    store: TrustStore,
    schemas: Path,
    *,
    now: datetime,
    skew: int = DEFAULT_SKEW,
    subject: str | None = None,
    audience: str | None = None,
) -> None:
    """The first failing step decides: schema, key owner, signature, issuer trust, validity window,
    subject, audience, status."""
    require_schema(schemas, "credential", document)
    verify_signed(document, store, document["issuer"])
    if store.trusted(document["issuer"]) is None:
        raise Rejected("ISSUER_UNTRUSTED")
    check_window(parse_time(document["issued_at"]), parse_time(document["expires_at"]), now, skew)
    if subject is not None and document["subject"] != subject:
        raise Rejected("SUBJECT_MISMATCH")
    carried = document.get("audience")
    if carried is not None and carried != audience:  # asked with no audience, or another one
        raise Rejected("AUDIENCE_MISMATCH")
    if not store.active(document["subject"], document["id"]):
        raise Rejected("CREDENTIAL_REVOKED")


# ---- delegation ----------------------------------------------------------------------------------------------------


def authority_for_subject(subject: str) -> str:
    """The issuer allowed to delegate for a subject: `org:{org}` for a native id, the subject itself otherwise."""
    native = _NATIVE_ID.fullmatch(subject)
    if native is not None:
        return f"org:{native.group(1)}"
    if subject.startswith("urn:chokr:org:"):  # a CHOKR prefix that fails its pattern is never downgraded
        raise Rejected("SCHEMA_INVALID")
    return subject


def _number(value: object) -> Decimal | None:
    return Decimal(str(value)) if isinstance(value, int | float) and not isinstance(value, bool) else None


def _members(value: object) -> set[str] | None:
    return {canonicalize(item).decode() for item in value} if isinstance(value, list) else None


def _narrower(op: str, parent: object, child: object) -> bool:
    """True when a child constraint value is as strict as the parent's under the same operator."""
    if op in ("lte", "lt"):
        p, c = _number(parent), _number(child)
        return p is not None and c is not None and c <= p
    if op in ("gte", "gt"):
        p, c = _number(parent), _number(child)
        return p is not None and c is not None and c >= p
    if op in ("in", "nin"):
        wider, narrower = _members(parent), _members(child)
        if wider is None or narrower is None:
            return False
        return narrower <= wider if op == "in" else narrower >= wider
    return canonicalize(parent) == canonicalize(child)  # eq, and any other operator only if identical


def _violation(parent: Mapping[str, Any], child: Mapping[str, Any]) -> str | None:
    """Why `child` is not covered by `parent` (same action and resource type), or `None` when it is."""
    for wanted in parent.get("constraints", []):
        same = [c for c in child.get("constraints", []) if c["path"] == wanted["path"] and c["op"] == wanted["op"]]
        if not any(_narrower(wanted["op"], wanted["value"], c["value"]) for c in same):
            return "AUDIENCE_OUT_OF_SCOPE" if wanted["path"] == "audience" else "CONSTRAINT_VIOLATED"
    return None


def check_covered(parent_grants: Sequence[Mapping[str, Any]], child_grants: Sequence[Mapping[str, Any]]) -> None:
    """Every child grant must be covered by a parent grant. No wildcards: action and resource type are equal, every
    constraint path of the parent is kept with an equal or narrower value, and a new path only narrows."""
    for child in child_grants:
        candidates = [
            p for p in parent_grants if p["action"] == child["action"] and p["resource_type"] == child["resource_type"]
        ]
        if not candidates:
            raise Rejected("DELEGATION_ESCALATION")
        reasons = [_violation(p, child) for p in candidates]
        if None not in reasons:
            raise Rejected(str(reasons[0]))


def _self_certifying(link: Mapping[str, Any]) -> Mapping[str, Mapping[str, Any]] | None:
    """The embedded keys of a link that takes the self-verifying path, or `None`. Accepted only when the delegator is
    the key id of the very key that signed and is also the issuer."""
    keys = {k["kid"]: k for k in link.get("keys", []) if "kid" in k}
    kid = str(_signatures(link)[0].get("kid"))
    key = keys.get(kid)
    if key is None or link["issuer"] != link["delegator"] or not link["delegator"].startswith(KEY_ID_PREFIX):
        return None
    try:
        same = hmac.compare_digest(link["delegator"], key_urn(key))
    except ValueError:
        return None
    return keys if same else None


def verify_chain(
    chain: Sequence[Mapping[str, Any]],
    leaf_subject: str,
    store: TrustStore,
    schemas: Path,
    *,
    now: datetime,
    skew: int = DEFAULT_SKEW,
    max_depth: int = 1,
    max_chain_depth: int = DEFAULT_MAX_CHAIN_DEPTH,
) -> None:
    """Checks in the stated order: depth, each link, linkage and cycles, authority, attenuation."""
    for link in chain:
        require_schema(schemas, "delegation", link)
    n = len(chain)
    if n < 1:
        raise Rejected("SCHEMA_INVALID")
    if n > max_chain_depth or n > max_depth or any(n - i > link.get("max_depth", 1) for i, link in enumerate(chain)):
        raise Rejected("DELEGATION_DEPTH_EXCEEDED")
    self_certifying = [_self_certifying(link) for link in chain]
    for link, embedded in zip(chain, self_certifying, strict=True):
        verify_signed(link, store, link["issuer"], embedded=embedded)
        if embedded is None and store.trusted(link["issuer"]) is None:
            raise Rejected("ISSUER_UNTRUSTED")
        check_window(parse_time(link["issued_at"]), parse_time(link["expires_at"]), now, skew)
        if not store.active(link["id"], link["delegator"]):
            raise Rejected("CREDENTIAL_REVOKED")
    for parent, child in itertools.pairwise(chain):
        if parent["delegatee"] != child["delegator"]:
            raise Rejected("SUBJECT_MISMATCH")
    if chain[-1]["delegatee"] != leaf_subject:
        raise Rejected("SUBJECT_MISMATCH")
    if len({link["id"] for link in chain}) != n:
        raise Rejected("DELEGATION_ESCALATION")  # the same delegation twice is a cycle
    for link, embedded in zip(chain, self_certifying, strict=True):
        if embedded is None and link["issuer"] != authority_for_subject(link["delegator"]):
            raise Rejected("ISSUER_MISMATCH")
    for parent, child in itertools.pairwise(chain):
        check_covered(parent["grant"], child["grant"])


# ---- evidence and passport -----------------------------------------------------------------------------------------


def verify_evidence(
    document: Mapping[str, Any],
    store: TrustStore,
    schemas: Path,
    *,
    now: datetime,
    skew: int = DEFAULT_SKEW,
    subject: str | None = None,
    artifact: str | None = None,
) -> dict[str, Any]:
    """Authenticity is checked (schema, key owner, signature, issuer trusted for this evidence type,
    subject, issue time, artifact digest, status); freshness is reported, never enforced, so that a policy can tell a
    stale item from a missing one. Returns `{status: fresh | stale}`, with `code: EVIDENCE_EXPIRED` when expired."""
    require_schema(schemas, "evidence", document)
    verify_signed(document, store, document["issuer"])
    relationship = store.trusted(document["issuer"], document["type"])
    if relationship is None:
        raise Rejected("ISSUER_UNTRUSTED")
    if subject is not None and document["subject"] != subject:
        raise Rejected("SUBJECT_MISMATCH")
    issued = parse_time(document["issued_at"])
    if issued > now + timedelta(seconds=skew):
        raise Rejected("EVIDENCE_INVALID")
    if artifact is not None and "sha256:" + hashlib.sha256(artifact.encode()).hexdigest() != document["digest"]:
        raise Rejected("EVIDENCE_INVALID")
    if not store.active(document["id"]):
        raise Rejected("EVIDENCE_INVALID")
    expires = document.get("expires_at")
    if expires is not None and now >= parse_time(expires) + timedelta(seconds=skew):
        return {"status": "stale", "code": "EVIDENCE_EXPIRED"}
    max_age = relationship.get("max_age_days")
    if max_age is not None and now - issued > timedelta(days=max_age):
        return {"status": "stale"}
    return {"status": "fresh"}


def _item(report: dict[str, Any], errors: list[str], item: Mapping[str, Any], identities: set[str], call: Any) -> None:
    try:
        report.update(call())
        if item.get("subject") not in identities:
            raise Rejected("SUBJECT_MISMATCH")  # an item about someone else; the other items are still checked
        report["accepted"] = True
    except Rejected as exc:
        report.update(accepted=False, code=exc.code)
        errors.append(exc.code)


def verify_passport(
    document: Mapping[str, Any],
    store: TrustStore,
    schemas: Path,
    *,
    now: datetime,
    skew: int = DEFAULT_SKEW,
) -> dict[str, Any]:
    """Every credential and every evidence item is verified on its own and bound to the agent, then the
    outer signature last: a valid outer signature never stands in for an invalid inner one. Stale evidence is reported
    and does not fail the passport; an expired or revoked credential does."""
    require_schema(schemas, "passport", document)
    identities = {document["agent"]["id"], *document.get("identifiers", [])}
    errors: list[str] = []
    credentials: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    for item in document.get("credentials", []):
        entry: dict[str, Any] = {"id": item.get("id")}
        credentials.append(entry)
        _item(entry, errors, item, identities, lambda i=item: _checked(verify_credential, i, store, schemas, now, skew))
    for item in document.get("evidence", []):
        entry = {"id": item.get("id")}
        evidence.append(entry)
        _item(entry, errors, item, identities, lambda i=item: _checked(verify_evidence, i, store, schemas, now, skew))
    outer = True
    try:
        verify_signed(document, store, document["issuer"])
        if store.trusted(document["issuer"]) is None:
            raise Rejected("ISSUER_UNTRUSTED")
    except Rejected as exc:
        outer = False
        errors.append(exc.code)
    ok = outer and all(c["accepted"] for c in credentials) and all(e["accepted"] for e in evidence)
    return {"ok": ok, "outer_signature": outer, "credentials": credentials, "evidence": evidence, "errors": errors}


def _checked(
    verify: Any, item: Mapping[str, Any], store: TrustStore, schemas: Path, now: datetime, skew: int
) -> dict[str, Any]:
    result = verify(item, store, schemas, now=now, skew=skew)
    return result if isinstance(result, dict) else {}


# ---- proof of possession and key binding ---------------------------------------------------------------------------


@dataclass
class NonceStore:
    """The challenges a verifier has issued and not yet seen answered. A nonce is consumed only by a proof that passed
    every other check, so a bad signature never uses one up."""

    issued: dict[str, Mapping[str, Any]] = field(default_factory=dict)
    consumed: dict[str, Mapping[str, Any]] = field(default_factory=dict)

    def consume(self, nonce: str) -> None:
        if nonce not in self.issued:
            raise Rejected("POP_REPLAYED")  # consumed before, or never issued
        self.consumed[nonce] = self.issued.pop(nonce)


def verify_pop(
    proof: Mapping[str, Any],
    nonces: NonceStore,
    registry: Mapping[str, Sequence[Mapping[str, Any]]],
    store: TrustStore,
    schemas: Path,
    *,
    now: datetime,
    skew: int = DEFAULT_SKEW,
    ttl_seconds: int = DEFAULT_POP_TTL,
    purpose: str | None = None,
    audience: str | None = None,
) -> None:
    """The first failure wins: the challenge is the one that was issued and within its lifetime;
    the time window; purpose and audience; the key is registered for the subject and not revoked; the signature; and
    only then the nonce is consumed."""
    require_schema(schemas, "pop", proof)
    challenge = proof["challenge"]
    given = nonces.issued.get(challenge["nonce"]) or nonces.consumed.get(challenge["nonce"])
    lifetime = parse_time(challenge["expires_at"]) - parse_time(challenge["issued_at"])
    if (given is not None and dict(given) != dict(challenge)) or lifetime > timedelta(seconds=ttl_seconds):
        raise Rejected("SCHEMA_INVALID")
    tolerance = timedelta(seconds=skew)
    if now < parse_time(challenge["issued_at"]) - tolerance:
        raise Rejected("POP_NOT_YET_VALID")
    if now >= parse_time(challenge["expires_at"]) + tolerance:
        raise Rejected("POP_EXPIRED")
    if purpose is not None and challenge.get("purpose") != purpose:
        raise Rejected("POP_WRONG_PURPOSE")
    if audience is not None and challenge["audience"] != audience:
        raise Rejected("AUDIENCE_MISMATCH")
    key = proof["key"]
    if thumbprint(key) not in {thumbprint(k) for k in registry.get(challenge["subject"], [])}:
        raise Rejected("POP_KEY_MISMATCH")
    if not store.active(key_urn(key)):
        raise Rejected("KEY_REVOKED")
    try:
        check_signature(key, proof["signature"], canonicalize(challenge))
    except Rejected as exc:
        raise Rejected("POP_SIGNATURE_INVALID") from exc
    nonces.consume(challenge["nonce"])


def bind_key(document: Mapping[str, Any], jwk: Mapping[str, Any]) -> dict[str, Any]:
    """Stamp `cnf.jkt` onto an unsigned document so the binding is inside the signed bytes."""
    if any(member in document for member in _SIGNATURE_MEMBERS):
        raise Rejected("SCHEMA_INVALID")
    return {**document, "cnf": {"jkt": thumbprint(jwk)}}


def confirm_binding(document: Mapping[str, Any], jwk: Mapping[str, Any]) -> None:
    """The key a verified proof of possession showed is the key the document is bound to."""
    cnf = document.get("cnf")
    jkt = cnf.get("jkt") if isinstance(cnf, Mapping) else None
    if not isinstance(jkt, str):
        raise Rejected("KEY_BINDING_ABSENT")
    if not hmac.compare_digest(jkt.encode(), thumbprint(jwk).encode()):
        raise Rejected("KEY_BINDING_MISMATCH")


# ---- authority epoch -----------------------------------------------------------------------------------------------


def verify_epoch(
    document: Mapping[str, Any],
    store: TrustStore,
    schemas: Path,
    high_water: dict[str, int],
    *,
    now: datetime,
    skew: int = DEFAULT_SKEW,
) -> None:
    """A signed epoch by the authority, trusted for `*`, within its time window. An older epoch than the
    highest one seen is a rollback and is always refused; an equal one changes nothing; a newer one advances the
    high-water mark. Only a verified document ever advances it."""
    require_schema(schemas, "epoch", document)
    verify_signed(document, store, document["authority"])
    if store.trusted(document["authority"]) is None:
        raise Rejected("ISSUER_UNTRUSTED")
    check_window(parse_time(document["issued_at"]), None, now, skew)
    if document.get("expires_at") is not None and now >= parse_time(document["expires_at"]) + timedelta(seconds=skew):
        raise Rejected("CREDENTIAL_EXPIRED")
    seen = high_water.get(document["authority"], 0)
    if document["epoch"] < seen:
        raise Rejected("AUTHORITY_EPOCH_ROLLBACK")
    high_water[document["authority"]] = max(seen, document["epoch"])


def check_credential_epoch(epoch: int | None, high_water: int, tolerance: str) -> dict[str, Any]:
    """A credential's epoch against the high-water mark (no epoch counts as 0). Older is stale; it is refused with
    `AUTHORITY_EPOCH_STALE` unless the tolerance is `allow_with_signal`. A newer one is `unconfirmed` and never
    raises the mark."""
    value = epoch or 0
    if value < high_water:
        if tolerance != "allow_with_signal":
            raise Rejected("AUTHORITY_EPOCH_STALE")
        return {"status": "stale"}
    return {"status": "current" if value == high_water else "unconfirmed"}
