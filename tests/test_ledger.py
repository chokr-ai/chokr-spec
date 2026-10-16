import copy

import pytest

from chokr_spec.errors import SpecError
from chokr_spec.ledger import GENESIS_PREV, ChainState, advance, make_record, record_hash, verify_chain

TS = "2026-01-01T00:00:00.000000Z"


def build(count: int = 4) -> list[dict]:
    state, records = ChainState("sdk:test"), []
    for n in range(count):
        record = make_record(state, "decision", {"n": n}, TS)
        advance(state, record)
        records.append(record)
    return records


def test_a_new_chain_starts_at_the_genesis_hash():
    first = build(1)[0]
    assert (first["seq"], first["prev_hash"]) == (0, GENESIS_PREV)


def test_each_record_commits_to_the_one_before():
    records = build()
    assert [r["prev_hash"] for r in records[1:]] == [r["hash"] for r in records[:-1]]
    assert verify_chain(records) == (True, None)


def test_the_hash_covers_the_header_fields():
    record = build(1)[0]
    assert record["hash"] == record_hash("sdk:test", 0, TS, "decision", record["body_digest"], GENESIS_PREV)


def test_body_modes():
    state = ChainState("c")
    full = make_record(state, "t", {"secret": 1}, TS)
    assert full["body"] == {"secret": 1}
    redacted = make_record(state, "t", {"secret": 1}, TS, body_mode="redacted", stored_body={"secret": "x"})
    assert redacted["body"] == {"secret": "x"}
    hidden = make_record(state, "t", {"secret": 1}, TS, body_mode="hash_only")
    assert "body" not in hidden
    assert hidden["body_digest"] == full["body_digest"]


def test_an_unknown_body_mode_is_refused():
    with pytest.raises(SpecError):
        make_record(ChainState("c"), "t", {}, TS, body_mode="partial")


def test_a_redacted_record_without_its_stored_body_is_refused():
    with pytest.raises(SpecError, match="stored_body"):
        make_record(ChainState("c"), "t", {"secret": 1}, TS, body_mode="redacted")


def test_a_chain_with_hidden_or_redacted_bodies_verifies():
    state, records = ChainState("c"), []
    for mode in ("full", "redacted", "hash_only"):
        record = make_record(state, "t", {"a": 1}, TS, body_mode=mode, stored_body={"a": "x"})
        advance(state, record)
        records.append(record)
    assert verify_chain(records) == (True, None)


def test_an_empty_chain_is_valid():
    assert verify_chain([]) == (True, None)


def mutated(change) -> tuple[bool, str | None]:
    records = copy.deepcopy(build())
    change(records)
    return verify_chain(records)


@pytest.mark.parametrize(
    ("change", "error"),
    [
        (lambda r: r[1]["body"].update(n=99), "body_mismatch at seq 1"),
        (lambda r: r.pop(2), "gap at seq 2"),
        (lambda r: r[2].update(seq=1), "gap at seq 2"),
        (lambda r: r[2].update(prev_hash="sha256:" + "f" * 64), "hash_break at seq 2 (prev_hash)"),
        (lambda r: r[1].update(hash="sha256:" + "a" * 64), "hash_break at seq 1"),
        (lambda r: r[3].update(chain_id="other"), "hash_break at seq 3 (chain_id changed)"),
        (lambda r: r[1].pop("body_digest"), "malformed at seq 1"),
        (lambda r: r[0].update(body={"x": float("nan")}), "malformed at seq 0"),
        (lambda r: r[1].update(seq=True), "malformed at seq 1"),
        (lambda r: r[1].update(seq=1.0), "malformed at seq 1"),
        (lambda r: r[1].update(ts=5), "malformed at seq 1"),
        (lambda r: r[1].update(body_mode="partial"), "malformed at seq 1"),
        (lambda r: r[1].pop("body"), "malformed at seq 1"),
        (lambda r: r[1].update(body_mode="hash_only"), "malformed at seq 1"),
    ],
)
def test_every_kind_of_change_is_found_at_the_first_bad_record(change, error):
    assert mutated(change) == (False, error)


def test_input_that_is_not_a_record_never_raises():
    assert verify_chain([None]) == (False, "malformed at seq 0")
    assert verify_chain([{"chain_id": "c"}]) == (False, "malformed at seq 0")


def test_the_chain_id_can_be_required():
    records = build()
    assert verify_chain(records, chain_id="sdk:test") == (True, None)
    assert verify_chain(records, chain_id="other") == (False, "chain_mismatch at seq 0")


def test_a_cut_short_chain_is_found_only_with_the_head_the_reader_knows():
    records = build()
    head = records[-1]["hash"]
    assert verify_chain(records[:2]) == (True, None)
    assert verify_chain(records, expected_head=head) == (True, None)
    assert verify_chain(records[:2], expected_head=head) == (False, "head_mismatch at seq 2")
    assert verify_chain([], expected_head=head) == (False, "head_mismatch at seq 0")
