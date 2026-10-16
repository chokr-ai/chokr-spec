"""What each vector area computes. `COMPUTE[area](vector, context)` returns the actual result in the shape of the
vector's `expected` object, and the runner compares the two. Another implementation reproduces the same results."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from chokr_spec.canonical import canonicalize, digest_object
from chokr_spec.errors import SpecError
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


COMPUTE: dict[str, Callable[[Vector, Context], dict[str, Any]]] = {
    "envelope": envelope,
    "ledger": ledger,
    "tamper": tamper,
    "schema": schema,
    "version": version,
    "verdict": verdict_signature,
}
# Areas whose expected values sit under these keys of the vector instead of under `expected`.
EXPECTED_KEYS = {"tamper": ("expected_error", "expected_seq")}
