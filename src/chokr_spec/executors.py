"""What each vector area computes. `COMPUTE[area](vector, context)` returns the actual result in the shape of the
vector's `expected` object, and the runner compares the two. Another implementation reproduces the same results."""

from __future__ import annotations

import hashlib
import json
import re
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
from chokr_spec.signatures import Rejected, b64url_decode, b64url_encode, verify_document
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


def _lf(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def anchor(vector: Vector, context: Context) -> dict[str, Any]:
    """The hash of an agent's locked instructions: the system and the developer segments, each with its
    line endings turned into LF and joined by one LF, hashed as the canonical form of
    `{"v": 1, "system": S, "developer": D}`. Nothing else is changed (no trimming, no Unicode normalization), so any
    real edit changes the hash."""
    given = vector["input"]
    system = "\n".join(_lf(text) for text in given["system"])
    developer = "\n".join(_lf(text) for text in given["developer"])
    return {
        "hash": digest_object({"v": 1, "system": system, "developer": developer}),
        "length": len(system.encode()) + len(developer.encode()),
    }


def lockhash(vector: Vector, context: Context) -> dict[str, Any]:
    """The three hashes that pin a tool definition. The description is hashed as received (no
    trimming, no Unicode normalization, a missing one is the empty string); the schema is the canonical form of
    `inputSchema`; the annotations hash covers the annotations, the output schema and the title together."""
    tool = vector["input"]["tool"]
    description = tool.get("description") or ""
    return {
        "description_hash": "sha256:" + hashlib.sha256(description.encode()).hexdigest(),
        "schema_hash": digest_object(tool.get("inputSchema")),
        "annotations_hash": digest_object(
            {
                "annotations": tool.get("annotations") or {},
                "outputSchema": tool.get("outputSchema"),
                "title": tool.get("title"),
            }
        ),
    }


_MESH_AGENT = re.compile(r"[a-z0-9][a-z0-9._:@-]{0,127}")
_MESH_RUN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@_-]{0,127}")
_MESH_SCOPE = re.compile(r"[a-z0-9][a-z0-9._:/@*-]{0,127}")
_MESH_TRACEPARENT = re.compile(r"00-([0-9a-f]{32})-[0-9a-f]{16}-[0-9a-f]{2}")
_MESH_PAYLOAD_KEYS = {"call_chain", "depth", "root_run_id", "restrictions"}
MESH_MAX_HEADER = 4096


def _mesh_scopes(restrictions: Any) -> list[str] | None:
    """The sorted scope set of a `restrictions` member, or `None` for none. Anything else is malformed."""
    if not isinstance(restrictions, dict) or set(restrictions) - {"scopes"}:
        raise ValueError("malformed")
    scopes = restrictions.get("scopes")
    if scopes is None:
        return None
    ok = isinstance(scopes, list) and len(scopes) <= 256
    if not ok or any(not isinstance(s, str) or _MESH_SCOPE.fullmatch(s) is None for s in scopes):
        raise ValueError("malformed")
    return sorted(set(scopes))


def _mesh_parse(headers: dict[str, str]) -> dict[str, Any]:
    lowered = {str(k).lower(): v for k, v in headers.items()}
    raw, parent = lowered.get("chokr-chain"), lowered.get("traceparent")
    if not isinstance(raw, str) or not isinstance(parent, str):
        return {"error": "malformed"}
    if len(raw) > MESH_MAX_HEADER:
        return {"error": "header_too_large"}
    matched = _MESH_TRACEPARENT.fullmatch(parent)
    if matched is None or matched.group(1) == "0" * 32:
        return {"error": "malformed"}
    try:
        payload = json.loads(b64url_decode(raw).decode("utf-8"))
        if not isinstance(payload, dict) or set(payload) != _MESH_PAYLOAD_KEYS:
            raise ValueError("malformed")
        chain, depth, root = payload["call_chain"], payload["depth"], payload["root_run_id"]
        bad_chain = not isinstance(chain, list) or not chain or len(chain) > 256
        if bad_chain or any(not isinstance(a, str) or _MESH_AGENT.fullmatch(a) is None for a in chain):
            raise ValueError("malformed")
        if isinstance(depth, bool) or not isinstance(depth, int):
            raise ValueError("malformed")
        if not isinstance(root, str) or _MESH_RUN.fullmatch(root) is None:
            raise ValueError("malformed")
        scopes = _mesh_scopes(payload["restrictions"])
    except ValueError, RecursionError:
        return {"error": "malformed"}
    return {
        "ok": True,
        "call_chain": chain,
        "depth": depth,
        "root_run_id": root,
        "scopes": scopes,
        "trace_id": matched.group(1),
    }


def meshchain(vector: Vector, context: Context) -> dict[str, Any]:
    """The `Chokr-Chain` header of the call chain. With `call_chain` in the input: the header is
    the unpadded base64url of the canonical JSON of `{call_chain, depth, root_run_id, restrictions}`, and `traceparent`
    is kept as given or made as `00-<trace_id>-<first 16 hex of sha256(trace_id + header)>-01`. With `headers`: the
    chain the headers carry, or the reason they are refused (`malformed`, `header_too_large`)."""
    given = vector["input"]
    if "headers" in given:
        return _mesh_parse(given["headers"])
    payload = {
        "call_chain": given["call_chain"],
        "depth": given["depth"],
        "root_run_id": given["root_run_id"],
        "restrictions": given["restrictions"],
    }
    canonical = canonicalize(payload)
    header = b64url_encode(canonical)
    made = hashlib.sha256((given["trace_id"] + header).encode("ascii")).hexdigest()[:16]
    out = {
        "jcs": canonical.decode(),
        "chokr_chain": header,
        "traceparent": given.get("traceparent") or f"00-{given['trace_id']}-{made}-01",
    }
    if given.get("tracestate"):
        out["tracestate"] = given["tracestate"]
    return out


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
    "anchor": anchor,
    "lockhash": lockhash,
    "meshchain": meshchain,
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
