import pytest

from chokr_spec.errors import SpecError
from chokr_spec.versioning import check_schema_version, parse_version


@pytest.mark.parametrize(("text", "parsed"), [("1.0", (1, 0)), ("1.12", (1, 12)), ("0.1", (0, 1)), ("2.0", (2, 0))])
def test_a_version_is_major_dot_minor(text, parsed):
    assert parse_version(text) == parsed


@pytest.mark.parametrize("value", ["1", "1.0.0", "01.0", "1.00", "v1.0", "", "1.0\n", " 1.0", 1.0, 1, None, ["1.0"]])
def test_anything_else_is_refused(value):
    with pytest.raises(SpecError):
        parse_version(value)


@pytest.mark.parametrize("given", ["1.0", "1.1", "1.2"])
def test_older_and_equal_minors_are_accepted(given):
    assert check_schema_version(given, supported="1.2") == given


@pytest.mark.parametrize("given", ["1.3", "2.0", "0.9"])
def test_a_newer_minor_and_another_major_are_refused(given):
    with pytest.raises(SpecError) as caught:
        check_schema_version(given, supported="1.2", name="verdict")
    assert caught.value.code == "SCHEMA_INVALID"
    assert "verdict" in caught.value.message


def test_a_missing_version_is_refused():
    with pytest.raises(SpecError, match="required"):
        check_schema_version(None)


def test_a_custom_error_code_is_kept():
    assert SpecError("x", code="OTHER").code == "OTHER"
