"""The ledger hash chain: every record commits to the record before it, so a change anywhere is detectable.

The hash of a record is the digest of the canonical JSON of `{chain_id, seq, ts, record_type, body_digest, prev_hash}`.
"""

from __future__ import annotations

import hmac
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from chokr_spec.canonical import digest_object
from chokr_spec.errors import SpecError

GENESIS_PREV = "sha256:" + "0" * 64
BODY_MODES = ("full", "redacted", "hash_only")


def record_hash(chain_id: str, seq: int, ts: str, record_type: str, body_digest: str, prev_hash: str) -> str:
    """The hash that identifies one record."""
    return digest_object(
        {
            "chain_id": chain_id,
            "seq": seq,
            "ts": ts,
            "record_type": record_type,
            "body_digest": body_digest,
            "prev_hash": prev_hash,
        }
    )


@dataclass
class ChainState:
    """Where a chain stands: the last written `seq` (the first record, the genesis, gets 0) and its hash."""

    chain_id: str
    seq: int = -1
    last_hash: str = GENESIS_PREV


def make_record(
    state: ChainState,
    record_type: str,
    body: dict[str, Any],
    ts: str,
    *,
    body_mode: str = "full",
    stored_body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the next record. Store it, then call `advance`.

    `body_digest` always covers the original `body`. With `body_mode` `redacted`, `stored_body` is what is written
    instead of the body, and it is required. With `hash_only`, no body is written.
    """
    if body_mode not in BODY_MODES:
        raise SpecError(f"unknown body_mode {body_mode!r}")
    seq = state.seq + 1
    body_digest = digest_object(body)
    record: dict[str, Any] = {
        "chain_id": state.chain_id,
        "seq": seq,
        "record_type": record_type,
        "ts": ts,
        "body_mode": body_mode,
        "body_digest": body_digest,
        "prev_hash": state.last_hash,
        "hash": record_hash(state.chain_id, seq, ts, record_type, body_digest, state.last_hash),
    }
    if body_mode == "full":
        record["body"] = body
    elif body_mode == "redacted":
        if stored_body is None:
            raise SpecError("a redacted record needs the stored_body to write")
        record["body"] = stored_body
    return record


def advance(state: ChainState, record: dict[str, Any]) -> None:
    """Move the chain state past a stored record."""
    state.seq, state.last_hash = record["seq"], record["hash"]


def _well_formed(record: Any) -> bool:
    """True when every field has the type the ledger schema gives it and the body matches the body mode."""
    if not isinstance(record, dict):
        return False
    texts = ("chain_id", "ts", "record_type", "body_digest", "prev_hash", "hash")
    if not all(isinstance(record.get(name), str) for name in texts):
        return False
    seq = record.get("seq")
    if not isinstance(seq, int) or isinstance(seq, bool) or record.get("body_mode") not in BODY_MODES:
        return False
    if record["body_mode"] == "hash_only":
        return "body" not in record
    return isinstance(record.get("body"), dict)


def verify_chain(
    records: Iterable[dict[str, Any]],
    *,
    genesis_prev: str = GENESIS_PREV,
    chain_id: str | None = None,
    expected_head: str | None = None,
) -> tuple[bool, str | None]:
    """Check a chain from `seq` 0. Returns `(True, None)`, or `(False, error)` for the first problem found.

    An error reads `<class> at seq <n>` with the class `gap`, `hash_break`, `body_mismatch`, `malformed`,
    `chain_mismatch` or `head_mismatch`. Bad input never raises.

    `chain_id`, when given, is the chain the records must belong to. `expected_head`, when given, is the hash of the
    last record the reader already knows. A chain cut short at the end still verifies on its own, because every record
    only commits to the ones before it, so a reader that must detect a cut keeps the head it last saw.
    """
    previous = genesis_prev
    count = 0
    first_chain = ""
    for index, record in enumerate(records):
        count = index + 1
        if not _well_formed(record):
            return False, f"malformed at seq {index}"
        try:
            if index == 0:
                first_chain = record["chain_id"]
                if chain_id is not None and first_chain != chain_id:
                    return False, "chain_mismatch at seq 0"
            if record["seq"] != index:
                return False, f"gap at seq {index}"
            if record["chain_id"] != first_chain:
                return False, f"hash_break at seq {index} (chain_id changed)"
            if not hmac.compare_digest(record["prev_hash"], previous):
                return False, f"hash_break at seq {index} (prev_hash)"
            # Only a stored full body can be hashed again, because the digest covers the original body.
            if record["body_mode"] == "full" and digest_object(record["body"]) != record["body_digest"]:
                return False, f"body_mismatch at seq {index}"
            expected = record_hash(
                record["chain_id"],
                record["seq"],
                record["ts"],
                record["record_type"],
                record["body_digest"],
                record["prev_hash"],
            )
            if not hmac.compare_digest(expected, record["hash"]):
                return False, f"hash_break at seq {index}"
            previous = record["hash"]
        except SpecError:
            return False, f"malformed at seq {index}"
    if expected_head is not None and previous != expected_head:
        return False, f"head_mismatch at seq {count}"
    return True, None
