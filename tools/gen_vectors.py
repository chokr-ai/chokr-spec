"""Write the conformance vectors that are produced by a script: envelope digests, the ledger chain, tampered chains,
version compatibility and signed verdicts.

The envelope, ledger and tamper vectors are computed here with `hashlib` and `json` only, apart from the checker they
test. The version and verdict vectors take their expected values from the reference checker, and a reviewer reads
them in the diff. The schema vectors are written by hand.

Run `python tools/gen_vectors.py` to rewrite them. The files are committed, so a change shows up in review.
"""

import base64
import copy
import hashlib
import json
import pathlib
from collections.abc import Callable
from typing import Any

from chokr_spec import data_dir
from chokr_spec.executors import COMPUTE, Context

ROOT = pathlib.Path(__file__).resolve().parents[1] / "vectors" / "core"
ZEROS = "sha256:" + "0" * 64


def canon(value: Any) -> str:
    """Canonical JSON for the inputs used here: keys in the basic plane, integers, strings, booleans and null."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value: Any) -> str:
    """`sha256:` followed by the hex digest of the canonical JSON of `value`."""
    return "sha256:" + hashlib.sha256(canon(value).encode("utf-8")).hexdigest()


def write(area: str, name: str, data: dict[str, Any]) -> None:
    """Write one vector file."""
    path = ROOT / area / f"{name}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")


def envelope_vectors() -> None:
    """Canonical form and digest of a call's arguments."""
    cases: dict[str, dict[str, Any]] = {
        "db_query_basic": {"sql": "SELECT 1"},
        "key_order": {"b": 2, "a": 1, "c": {"z": [1, 2, 3], "y": None}},
        "unicode": {"name": "caf\u00e9", "emoji_free": "\u00fc\u00f1\u00ee"},
        "empty": {},
        "nested_list": {"items": [{"id": 1}, {"id": 2}], "flag": True},
    }
    for name, arguments in cases.items():
        write(
            "envelope",
            name,
            {
                "id": f"envelope/{name}",
                "level": "core",
                "input": {"arguments": arguments},
                "expected": {"canonical": canon(arguments), "arguments_digest": digest(arguments)},
            },
        )


def anchor_vectors() -> None:
    """The hash of locked instructions. Expected values are computed here with `hashlib` and `json` only."""

    def lf(text: str) -> str:
        return text.replace("\r\n", "\n").replace("\r", "\n")

    def expected(system: list[str], developer: list[str]) -> dict[str, Any]:
        s, d = "\n".join(lf(x) for x in system), "\n".join(lf(x) for x in developer)
        return {"hash": digest({"v": 1, "system": s, "developer": d}), "length": len(s.encode()) + len(d.encode())}

    cases: dict[str, tuple[list[str], list[str]]] = {
        "basic": (["You are a helpful agent."], ["Use the tools carefully."]),
        "no_developer_text": (["You are a helpful agent."], []),
        "no_instructions": ([], []),
        "two_system_segments_are_joined_by_one_lf": (["First rule.", "Second rule."], []),
        "crlf_hashes_like_lf": (["line one\r\nline two"], []),
        "lf_hashes_like_crlf": (["line one\nline two"], []),
        "lone_cr_is_a_line_ending": (["line one\rline two"], []),
        "a_cr_that_ends_a_segment_is_converted_before_the_join": (["rule\r", "next"], []),
        "trailing_space_changes_the_hash": (["You are a helpful agent. "], ["Use the tools carefully."]),
        "one_character_edit_changes_the_hash": (["You are a helpful agent!"], ["Use the tools carefully."]),
        "system_and_developer_are_not_interchangeable": ([], ["You are a helpful agent."]),
        "composed_letter": (["café"], []),
        "decomposed_letter": (["café"], []),
        "non_ascii_and_control_characters": (["naïve — 日本語 \U0001f600 \u0001 \u007f"], ["\u2028"]),
        "quotes_and_backslashes": (['say "hi" \\ done'], []),
    }
    for name, (system, developer) in cases.items():
        write(
            "anchor",
            name,
            {
                "id": f"anchor/{name}",
                "level": "core",
                "input": {"system": system, "developer": developer},
                "expected": expected(system, developer),
            },
        )


def chain(chain_id: str, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The stored records of a chain that starts at the genesis hash."""
    out: list[dict[str, Any]] = []
    previous = ZEROS
    for seq, item in enumerate(records):
        body_digest = digest(item["body"])
        record_hash = digest(
            {
                "chain_id": chain_id,
                "seq": seq,
                "ts": item["ts"],
                "record_type": item["record_type"],
                "body_digest": body_digest,
                "prev_hash": previous,
            }
        )
        record: dict[str, Any] = {
            "chain_id": chain_id,
            "seq": seq,
            "record_type": item["record_type"],
            "ts": item["ts"],
            "body_mode": item.get("body_mode", "full"),
            "body_digest": body_digest,
            "prev_hash": previous,
            "hash": record_hash,
        }
        if record["body_mode"] == "full":
            record["body"] = item["body"]
        elif record["body_mode"] == "redacted":
            record["body"] = item["stored_body"]
        out.append(record)
        previous = record_hash
    return out


def ledger_vectors() -> list[dict[str, Any]]:
    """A four-record chain, returned so that the tampered variants can start from it."""
    chain_id = "sdk:01J0000000000000000000000A"
    records: list[dict[str, Any]] = [
        {"record_type": "genesis", "body": {"note": "start"}, "ts": "2026-01-01T00:00:00.000000Z"},
        {"record_type": "decision", "body": {"outcome": "allow", "n": 1}, "ts": "2026-01-01T00:00:01.000000Z"},
        {"record_type": "decision", "body": {"outcome": "deny", "n": 2}, "ts": "2026-01-01T00:00:02.000000Z"},
        {"record_type": "outcome", "body": {"ok": True}, "ts": "2026-01-01T00:00:03.000000Z", "body_mode": "hash_only"},
    ]
    built = chain(chain_id, records)
    write(
        "ledger",
        "four_records",
        {
            "id": "ledger/four_records",
            "level": "core",
            "chain_id": chain_id,
            "records": records,
            "expected": {"hashes": [record["hash"] for record in built]},
        },
    )
    return built


def redacted_ledger_vector() -> None:
    """A chain whose middle record stores a redacted copy of its body, with the hash of the original body."""
    chain_id = "sdk:01J0000000000000000000000B"
    records: list[dict[str, Any]] = [
        {"record_type": "genesis", "body": {"note": "start"}, "ts": "2026-01-01T00:00:00.000000Z"},
        {
            "record_type": "decision",
            "body": {"outcome": "deny", "card": "4111111111111111"},
            "stored_body": {"outcome": "deny", "card": "[removed]"},
            "ts": "2026-01-01T00:00:01.000000Z",
            "body_mode": "redacted",
        },
    ]
    built = chain(chain_id, records)
    write(
        "ledger",
        "redacted_body",
        {
            "id": "ledger/redacted_body",
            "level": "core",
            "chain_id": chain_id,
            "records": records,
            "expected": {"hashes": [record["hash"] for record in built], "chain_verifies": True},
        },
    )


def tamper_vectors(good: list[dict[str, Any]]) -> None:
    """Chains that were changed after they were written, each with the error a checker must report."""

    def case(name: str, kind: str, seq: int, mutate: Callable[[list[dict[str, Any]]], None]) -> None:
        records = copy.deepcopy(good)
        mutate(records)
        write(
            "tamper",
            name,
            {
                "id": f"tamper/{name}",
                "level": "core",
                "records": records,
                "expected_error": kind,
                "expected_seq": seq,
            },
        )

    def flip_body(records: list[dict[str, Any]]) -> None:
        records[1]["body"]["outcome"] = "deny"

    def drop_record(records: list[dict[str, Any]]) -> None:
        del records[2]

    def alter_prev(records: list[dict[str, Any]]) -> None:
        records[2]["prev_hash"] = "sha256:" + "f" * 64

    def alter_hash(records: list[dict[str, Any]]) -> None:
        records[1]["hash"] = "sha256:" + "a" * 64

    def drop_field(records: list[dict[str, Any]]) -> None:
        del records[1]["body_digest"]

    def decrement_seq(records: list[dict[str, Any]]) -> None:
        records[2]["seq"] = 1

    def boolean_seq(records: list[dict[str, Any]]) -> None:
        records[1]["seq"] = True

    def unknown_mode(records: list[dict[str, Any]]) -> None:
        records[1]["body_mode"] = "partial"

    def hidden_body_present(records: list[dict[str, Any]]) -> None:
        records[3]["body"] = {"ok": True}

    def timestamp_not_text(records: list[dict[str, Any]]) -> None:
        records[1]["ts"] = 5

    case("body_changed", "body_mismatch", 1, flip_body)
    case("record_removed", "gap", 2, drop_record)
    case("prev_hash_altered", "hash_break", 2, alter_prev)
    case("hash_altered", "hash_break", 1, alter_hash)
    case("field_missing", "malformed", 1, drop_field)
    case("seq_decremented", "gap", 2, decrement_seq)
    case("seq_is_a_boolean", "malformed", 1, boolean_seq)
    case("unknown_body_mode", "malformed", 1, unknown_mode)
    case("hash_only_record_with_a_body", "malformed", 3, hidden_body_present)
    case("timestamp_is_not_text", "malformed", 1, timestamp_not_text)


def computed(level: str, area: str, name: str, given: dict[str, Any]) -> None:
    """Write a vector whose expected value is what the reference checker computes for `given`."""
    vector: dict[str, Any] = {"input": given}
    vector["expected"] = COMPUTE[area](vector, Context(schemas=data_dir() / "schemas"))
    vector["id"] = f"{area}/{name}"
    vector["level"] = level
    path = ROOT.parent / level / area / f"{name}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(vector, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )


def version_vectors() -> None:
    """Which versions a reader that supports one version accepts."""
    cases: list[tuple[str, str, Any]] = [
        ("same", "1.0", "1.0"),
        ("older_minor", "1.2", "1.1"),
        ("equal_minor", "1.2", "1.2"),
        ("higher_minor", "1.0", "1.1"),
        ("next_major", "1.0", "2.0"),
        ("previous_major", "1.0", "0.9"),
        ("missing", "1.0", None),
        ("no_minor", "1.0", "1"),
        ("number_not_string", "1.0", 1.0),
        ("leading_zero", "1.0", "1.00"),
        ("text", "1.0", "latest"),
        ("three_parts", "1.0", "1.0.0"),
        ("trailing_newline", "1.0", "1.0\n"),
    ]
    for name, supported, given in cases:
        computed("core", "version", name, {"supported": supported, "version": given})


def b64(data: bytes) -> str:
    """Unpadded base64url text."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def verdict_vectors() -> None:
    """Signed verdicts that must be accepted, and the ways a verdict can be rejected."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    seeds = {"k1": bytes(range(32)), "k2": bytes(range(1, 33))}
    keys = {kid: Ed25519PrivateKey.from_private_bytes(seed) for kid, seed in seeds.items()}

    def jwk(kid: str, **over: Any) -> dict[str, Any]:
        raw = keys[kid].public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return {"kty": "OKP", "crv": "Ed25519", "kid": kid, "alg": "EdDSA", "x": b64(raw), **over}

    def sign(document: dict[str, Any], kid: str = "k1") -> dict[str, Any]:
        value = b64(keys[kid].sign(canon(document).encode("utf-8")))
        return {**document, "signature": {"alg": "EdDSA", "kid": kid, "value": value}}

    body = {
        "schema_version": "1.0",
        "verdict_id": "ver_1",
        "envelope_id": "env_1",
        "outcome": "allow",
        "decided_by": "engine",
        "reason_codes": ["POLICY_SATISFIED"],
        "unicode": "caf\u00e9",
        "n": 1,
    }
    jwks = {"keys": [jwk("k1"), jwk("k2")]}
    signed = sign(body)
    signature = signed["signature"]
    other = sign(body, "k2")
    value = signature["value"]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    # A signature whose text uses `-` or `_`, so that the standard alphabet can be swapped in for it.
    with_url_chars = next(
        sign({**body, "n": n}) for n in range(2, 200) if {"-", "_"} & set(sign({**body, "n": n})["signature"]["value"])
    )
    standard = with_url_chars["signature"]["value"].replace("-", "+").replace("_", "/")
    # The last character holds four unused bits, which must be zero.
    loose_end = value[:-1] + alphabet[alphabet.index(value[-1]) | 1]

    def with_value(text: str, document: dict[str, Any] = signed) -> dict[str, Any]:
        return {"document": {**document, "signature": {**document["signature"], "value": text}}}

    cases: dict[str, dict[str, Any]] = {
        "valid": {"document": signed},
        "valid_other_key": {"document": other},
        "valid_key_order_does_not_matter": {"document": dict(reversed(list(signed.items())))},
        "tampered_outcome": {"document": {**signed, "outcome": "deny"}},
        "tampered_added_field": {"document": {**signed, "extra": True}},
        "unsigned": {"document": body},
        "alg_none": {"document": {**signed, "signature": {**signature, "alg": "none"}}},
        "alg_hs256": {"document": {**signed, "signature": {**signature, "alg": "HS256"}}},
        "unknown_kid": {"document": {**signed, "signature": {**signature, "kid": "k9"}}},
        "unknown_kid_not_allowed": {
            "document": {**signed, "signature": {**signature, "kid": "k9"}},
            "allowed_kids": ["k2"],
        },
        "kid_not_allowed": {"document": signed, "allowed_kids": ["k2"]},
        "kid_allowed": {"document": signed, "allowed_kids": ["k1"]},
        "wrong_key_for_kid": {"document": {**other, "signature": {**other["signature"], "kid": "k1"}}},
        "signature_not_base64": {"document": {**signed, "signature": {**signature, "value": "!!!"}}},
        "signature_object_malformed": {"document": {**signed, "signature": "oops"}},
        "signature_with_whitespace": with_value(value[:4] + "\n" + value[4:]),
        "signature_with_padding": with_value(value + "=="),
        "signature_in_the_standard_alphabet": with_value(standard, with_url_chars),
        "signature_with_unused_bits_set": with_value(loose_end),
        "key_with_other_algorithm": {
            "document": {**signed, "signature": {**signature, "alg": "ES256"}},
            "jwks": {"keys": [jwk("k1", alg="ES256")]},
        },
    }
    for name, given in cases.items():
        computed("connect", "verdict", name, {"jwks": given.pop("jwks", jwks), **given})


def pattern_vectors() -> None:
    """Documents that end in a newline: a text pattern must match the whole text, so each of them is invalid."""
    committed = data_dir() / "vectors" / "core" / "schema" / "ledger_record_valid.json"
    base = json.loads(committed.read_text("utf-8"))["input"]["document"]
    cases = {
        "ledger_record_hash_ends_with_a_newline": {**base, "hash": base["hash"] + "\n"},
        "ledger_record_version_ends_with_a_newline": {**base, "schema_version": "1.0\n"},
        "ledger_record_timestamp_is_not_a_timestamp": {**base, "ts": "yesterday"},
        "ledger_record_timestamp_has_an_offset": {**base, "ts": "2026-01-01T00:00:00+01:00"},
    }
    for name, document in cases.items():
        computed("core", "schema", name, {"schema": "ledger_record", "document": document})


if __name__ == "__main__":
    envelope_vectors()
    anchor_vectors()
    tamper_vectors(ledger_vectors())
    redacted_ledger_vector()
    version_vectors()
    verdict_vectors()
    pattern_vectors()
    print("vectors written to", ROOT.parent)
