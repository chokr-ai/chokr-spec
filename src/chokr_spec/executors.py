"""What each vector area computes. `COMPUTE[area](vector, context)` returns the actual result in the shape of the
vector's `expected` object, and the runner compares the two. Another implementation reproduces the same results."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from chokr_spec import interop, trust
from chokr_spec.canonical import canonicalize, digest_object
from chokr_spec.errors import SpecError
from chokr_spec.keys import thumbprint
from chokr_spec.ledger import ChainState, advance, make_record, verify_chain
from chokr_spec.signatures import Rejected, verify_document
from chokr_spec.versioning import check_schema_version

Vector = dict[str, Any]


@dataclass(frozen=True)
class Context:
    """What executors need besides the vector: the folder that holds the JSON Schemas."""

    schemas: Path


def envelope(vector: Vector, context: Context) -> dict[str, Any]:
    """The canonical form and the digest of a call's arguments."""
    arguments = vector["input"]["arguments"]
    return {"canonical": canonicalize(arguments).decode(), "arguments_digest": digest_object(arguments)}


def ledger(vector: Vector, context: Context) -> dict[str, Any]:
    """The record hashes of a chain built from the listed records, and whether that chain verifies."""
    state, hashes, records = ChainState(vector["chain_id"]), [], []
    for item in vector["records"]:
        record = make_record(
            state,
            item["record_type"],
            item["body"],
            item["ts"],
            body_mode=item.get("body_mode", "full"),
            stored_body=item.get("stored_body"),
        )
        advance(state, record)
        hashes.append(record["hash"])
        records.append(record)
    return {"hashes": hashes, "chain_verifies": verify_chain(records) == (True, None)}


def tamper(vector: Vector, context: Context) -> dict[str, Any]:
    """The class of error and the `seq` where a chain that was changed after it was written first fails."""
    ok, error = verify_chain(vector["records"])
    if ok or error is None:
        return {"expected_error": None, "expected_seq": None}
    kind, _, rest = error.partition(" at seq ")
    return {"expected_error": kind, "expected_seq": int(rest.split(" ", 1)[0])}


def schema(vector: Vector, context: Context) -> dict[str, Any]:
    """Whether a document is valid under the named schema."""
    document = json.loads((context.schemas / f"{vector['input']['schema']}.schema.json").read_text("utf-8"))
    Draft202012Validator.check_schema(document)
    return {"valid": Draft202012Validator(document).is_valid(vector["input"]["document"])}


def version(vector: Vector, context: Context) -> dict[str, Any]:
    """Whether a reader that supports one version accepts a document of another."""
    given = vector["input"]
    try:
        check_schema_version(given.get("version"), supported=given.get("supported", "1.0"))
    except SpecError as exc:
        return {"accepted": False, "code": exc.code}
    return {"accepted": True}


def verdict_signature(vector: Vector, context: Context) -> dict[str, Any]:
    """Whether a signed verdict is accepted, or the code that rejects it."""
    given = vector["input"]
    keys = {key["kid"]: key for key in given["jwks"]["keys"]}
    try:
        verify_document(given["document"], keys, given.get("allowed_kids"))
    except Rejected as exc:
        return {"accepted": False, "code": exc.code}
    return {"accepted": True}


# ---- trust level ---------------------------------------------------------------------------------------------------
# Every area takes `input` (documents, the trust config, `now`, optionally `clock_skew_seconds`) and returns what a
# verifier decides: `accepted` (or `valid`, `confirmed`, `bound`, `ok`) and the `code` of the first failing check.


def _outcome(key: str, call: Callable[[], dict[str, Any] | None]) -> dict[str, Any]:
    try:
        return {key: True, **(call() or {})}
    except Rejected as exc:
        return {key: False, "code": exc.code}


def _setup(given: dict[str, Any], context: Context) -> tuple[trust.TrustStore, datetime, int]:
    store = trust.TrustStore.load(given["trust"], context.schemas)
    return store, trust.parse_time(given["now"]), trust.check_skew(given.get("clock_skew_seconds", trust.DEFAULT_SKEW))


def crypto(vector: Vector, context: Context) -> dict[str, Any]:
    """Whether the signature, or every hybrid proof, over the canonical form of `payload` verifies with the keys."""
    given = vector["input"]
    keys = {k["kid"]: k for k in given["keys"]}
    message = canonicalize(given["payload"])

    def call() -> None:
        proofs = given.get("proofs")
        if proofs is not None and (len(proofs) < 2 or len({p["kid"] for p in proofs}) != len(proofs)):
            raise Rejected("SCHEMA_INVALID")  # a hybrid signature needs two proofs: removing one fails closed
        for signature in proofs if proofs is not None else [given["signature"]]:
            jwk = keys.get(signature["kid"])
            if jwk is None:
                raise Rejected("KEY_NOT_FOUND")
            trust.check_signature(jwk, signature, message)

    return _outcome("valid", call)


def jws(vector: Vector, context: Context) -> dict[str, Any]:
    """Whether a compact JWS verifies, or the code that rejects it."""
    given = vector["input"]

    def call() -> dict[str, Any]:
        skew = trust.check_skew(given.get("clock_skew_seconds", trust.DEFAULT_SKEW))
        return {"claims": interop.verify_compact(given["token"], given["keys"], now=given["now"], skew=skew)}

    return _outcome("accepted", call)


def thumbprint_of(vector: Vector, context: Context) -> dict[str, Any]:
    """The RFC 7638 thumbprint of a public key, as `sha256:` and hex."""
    return {"thumbprint": thumbprint(vector["input"]["jwk"])}


def credential(vector: Vector, context: Context) -> dict[str, Any]:
    """Whether a credential is accepted for a subject and audience, or the code of the first failing check."""
    given = vector["input"]

    def call() -> None:
        store, now, skew = _setup(given, context)
        trust.verify_credential(
            given["document"],
            store,
            context.schemas,
            now=now,
            skew=skew,
            subject=given.get("subject"),
            audience=given.get("audience"),
        )

    return _outcome("accepted", call)


def delegation(vector: Vector, context: Context) -> dict[str, Any]:
    """Whether a delegation chain reaches the leaf subject with attenuated authority, or the code that stops it."""
    given = vector["input"]

    def call() -> None:
        store, now, skew = _setup(given, context)
        trust.verify_chain(
            given["chain"],
            given["leaf_subject"],
            store,
            context.schemas,
            now=now,
            skew=skew,
            max_depth=given.get("max_depth", 1),
            max_chain_depth=given.get("max_chain_depth", trust.DEFAULT_MAX_CHAIN_DEPTH),
        )

    return _outcome("accepted", call)


def evidence(vector: Vector, context: Context) -> dict[str, Any]:
    """Whether an evidence item is authentic, and whether it is fresh or stale."""
    given = vector["input"]

    def call() -> dict[str, Any]:
        store, now, skew = _setup(given, context)
        return trust.verify_evidence(
            given["document"],
            store,
            context.schemas,
            now=now,
            skew=skew,
            subject=given.get("subject"),
            artifact=given.get("artifact"),
        )

    return _outcome("accepted", call)


def passport(vector: Vector, context: Context) -> dict[str, Any]:
    """The report of an independent verification of a passport: every inner item, then the outer signature."""
    given = vector["input"]
    try:
        store, now, skew = _setup(given, context)
        return trust.verify_passport(given["document"], store, context.schemas, now=now, skew=skew)
    except Rejected as exc:
        return {"ok": False, "errors": [exc.code]}


def pop(vector: Vector, context: Context) -> dict[str, Any]:
    """The result of each proof of possession, in order, against a verifier that issued the listed challenges."""
    given = vector["input"]
    store = trust.TrustStore.load(given["trust"], context.schemas)
    nonces = trust.NonceStore({c["nonce"]: c for c in given["challenges"]})
    skew = trust.check_skew(given.get("clock_skew_seconds", trust.DEFAULT_SKEW))

    def one(attempt: dict[str, Any]) -> dict[str, Any]:
        return _outcome(
            "accepted",
            lambda: trust.verify_pop(
                attempt["proof"],
                nonces,
                given["registry"],
                store,
                context.schemas,
                now=trust.parse_time(attempt["now"]),
                skew=skew,
                ttl_seconds=given.get("ttl_seconds", trust.DEFAULT_POP_TTL),
                purpose=attempt.get("purpose"),
                audience=attempt.get("audience"),
            ),
        )

    return {"results": [one(attempt) for attempt in given["attempts"]]}


def keybinding(vector: Vector, context: Context) -> dict[str, Any]:
    """Stamp a document with `cnf.jkt` (`op: bind`), or confirm that a proven key is the one it is bound to."""
    given = vector["input"]
    if given["op"] == "bind":
        return _outcome("bound", lambda: {"document": trust.bind_key(given["document"], given["key"])})
    return _outcome("confirmed", lambda: trust.confirm_binding(given["document"], given["key"]))


def epoch(vector: Vector, context: Context) -> dict[str, Any]:
    """An authority epoch document against the high-water mark (`op: document`), or a credential's epoch."""
    given = vector["input"]
    if given["op"] == "credential":
        return _outcome(
            "accepted",
            lambda: trust.check_credential_epoch(given.get("epoch"), given["high_water"], given["tolerance"]),
        )
    high_water = dict(given["high_water"])

    def call() -> None:
        store, now, skew = _setup(given, context)
        trust.verify_epoch(given["document"], store, context.schemas, high_water, now=now, skew=skew)

    return {**_outcome("accepted", call), "high_water": high_water}


def vc(vector: Vector, context: Context) -> dict[str, Any]:
    """A W3C Data Integrity proof: verify it (`verify`), or recompute its hashes (`hashes`) or `proofValue` (`sign`)."""
    given = vector["input"]
    if given["op"] == "hashes":
        return interop.integrity_hashes(given["document"])
    if given["op"] == "sign":
        return {"proof_value": interop.sign_integrity_eddsa(given["document"], given["secret"])}
    return _outcome("accepted", lambda: interop.verify_integrity(given["document"], given["jwk"]))


def sdjwt(vector: Vector, context: Context) -> dict[str, Any]:
    """An SD-JWT: the digest of a disclosure (`digest`), or whether a presentation verifies, and what it discloses."""
    given = vector["input"]
    if given["op"] == "digest":
        return {"digest": interop.sd_digest(given["disclosure"])}
    return _outcome(
        "accepted",
        lambda: {"claims": interop.verify_sd_jwt(given["presentation"], given["keys"], now=given["now"])},
    )


COMPUTE: dict[str, Callable[[Vector, Context], dict[str, Any]]] = {
    "envelope": envelope,
    "ledger": ledger,
    "tamper": tamper,
    "schema": schema,
    "version": version,
    "verdict": verdict_signature,
    "crypto": crypto,
    "jws": jws,
    "thumbprint": thumbprint_of,
    "credential": credential,
    "delegation": delegation,
    "evidence": evidence,
    "passport": passport,
    "pop": pop,
    "keybinding": keybinding,
    "epoch": epoch,
    "vc": vc,
    "sdjwt": sdjwt,
}
# Areas whose expected values sit under these keys of the vector instead of under `expected`.
EXPECTED_KEYS = {"tamper": ("expected_error", "expected_seq")}
