"""These tests need the language package. They run when it is installed next to this repo and are skipped otherwise.

Install it with `uv pip install -e ../chokr-policy-language`.
"""

import json

import pytest
from ruamel.yaml import YAML

from chokr_spec import data_dir

registry = pytest.importorskip("cplang.registry")


def entries(name: str) -> set[str]:
    data = YAML(typ="safe").load((data_dir() / "registry" / f"{name}.yaml").read_text("utf-8"))
    return {str(entry.get("code") or entry.get("name")) for entry in data["entries"]}


def test_the_verdict_schema_allows_every_outcome_of_the_language():
    schema = json.loads((data_dir() / "schemas" / "verdict.schema.json").read_text("utf-8"))
    assert set(registry.OUTCOMES) <= set(schema["properties"]["outcome"]["enum"])


def test_chokr_defines_no_reason_code_that_the_language_defines():
    assert entries("reason_codes").isdisjoint(registry.REASON_CODES)


def test_chokr_defines_no_error_code_that_the_language_defines():
    cplang_errors = pytest.importorskip("cplang.errors")
    language_codes = {cplang_errors.CplError.code, "SCHEMA_INVALID", "EVALUATION_ERROR", "VOCABULARY_UNKNOWN_VALUE"}
    assert entries("error_codes").isdisjoint(language_codes)
