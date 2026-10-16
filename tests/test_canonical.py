import pytest

from chokr_spec.canonical import MAX_DEPTH, canonicalize, digest_bytes, digest_object
from chokr_spec.errors import CanonicalizationError


def test_keys_are_sorted_and_whitespace_is_removed():
    assert canonicalize({"b": 2, "a": [1, {"z": None, "y": True}]}) == b'{"a":[1,{"y":true,"z":null}],"b":2}'


def test_text_is_written_as_utf8():
    assert canonicalize({"name": "caf\u00e9"}) == '{"name":"café"}'.encode()


def test_digest_of_the_empty_object_is_known():
    assert digest_object({}) == "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
    assert digest_bytes(b"{}") == digest_object({})


def test_the_same_value_always_has_the_same_digest():
    assert digest_object({"a": 1, "b": 2}) == digest_object({"b": 2, "a": 1})


@pytest.mark.parametrize("value", [float("nan"), float("inf"), object(), {1, 2}, {(1, 2): 3}])
def test_values_that_are_not_json_are_refused(value):
    with pytest.raises(CanonicalizationError) as caught:
        canonicalize({"x": value})
    assert caught.value.code == "CANONICALIZATION_ERROR"


def test_nesting_is_limited():
    value: object = "leaf"
    for _ in range(MAX_DEPTH):
        value = [value]
    assert canonicalize(value)
    with pytest.raises(CanonicalizationError):
        canonicalize([value])


def test_a_lower_limit_can_be_set():
    with pytest.raises(CanonicalizationError):
        canonicalize([[[1]]], max_depth=2)
    assert canonicalize([[1]], max_depth=2) == b"[[1]]"


@pytest.mark.parametrize("limit", [0, MAX_DEPTH + 1])
def test_the_limit_has_bounds(limit):
    with pytest.raises(ValueError):
        canonicalize({}, max_depth=limit)


def test_tuples_count_as_lists():
    assert canonicalize({"a": (1, 2)}) == b'{"a":[1,2]}'
