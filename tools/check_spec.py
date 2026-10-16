"""Check the protocol data as a whole. Exits 1 and lists every problem when any check fails.

- every schema is valid Draft 2020-12, has the `$id` its file name implies, rejects unknown properties, requires its
  version field and is used by at least one schema vector;
- every vector is valid JSON with a unique `id` and `level` that match its path, and an area that the reference checker
  can run;
- every registry has a schema version and sorted, unique entries;
- every vector passes the reference checker.
"""

import json
import pathlib
import sys
from typing import Any

from jsonschema import Draft202012Validator
from ruamel.yaml import YAML

from chokr_spec import data_dir
from chokr_spec.executors import COMPUTE
from chokr_spec.runner import run

ID_BASE = "https://spec.chokr.dev/schemas"
DIALECT = "https://json-schema.org/draft/2020-12/schema"


def schema_problems(root: pathlib.Path, referenced: set[str]) -> list[str]:
    """Problems in the JSON Schemas: validity, `$id` and use by at least one vector."""
    problems: list[str] = []
    for path in sorted((root / "schemas").glob("*.schema.json")):
        name = path.name.removesuffix(".schema.json")
        document = json.loads(path.read_text("utf-8"))
        try:
            Draft202012Validator.check_schema(document)
        except Exception as exc:  # the validator raises several types; the type name is what matters
            problems.append(f"schemas/{path.name}: not a valid schema ({type(exc).__name__})")
        if document.get("$id") != f"{ID_BASE}/{name}/1.0":
            problems.append(f"schemas/{path.name}: $id is {document.get('$id')!r}, expected {ID_BASE}/{name}/1.0")
        if document.get("$schema") != DIALECT:
            problems.append(f"schemas/{path.name}: is not Draft 2020-12")
        if document.get("additionalProperties") is not False:
            problems.append(f"schemas/{path.name}: allows unknown properties")
        required = document.get("required", [])
        if name != "plugin_manifest" and not {"schema_version", "schema"} & set(required):
            problems.append(f"schemas/{path.name}: does not require schema_version or schema")
        if name not in referenced:
            problems.append(f"schemas/{path.name}: no vector uses this schema")
    return problems


def vector_problems(root: pathlib.Path) -> tuple[list[str], set[str]]:
    """Problems in the vector files, and the names of the schemas the schema vectors use."""
    problems: list[str] = []
    referenced: set[str] = set()
    seen: dict[str, pathlib.Path] = {}
    for path in sorted((root / "vectors").rglob("*.json")):
        shown = path.relative_to(root).as_posix()
        try:
            vector: Any = json.loads(path.read_text("utf-8"))
        except ValueError:
            problems.append(f"{shown}: not valid JSON")
            continue
        vector_id = vector.get("id") if isinstance(vector, dict) else None
        if not isinstance(vector_id, str) or not vector_id:
            problems.append(f"{shown}: no id")
            continue
        if vector_id in seen:
            problems.append(f"{shown}: id {vector_id!r} is also used by {seen[vector_id].relative_to(root).as_posix()}")
        seen[vector_id] = path
        if vector_id != f"{path.parent.name}/{path.stem}":
            problems.append(f"{shown}: id is {vector_id!r}, expected '{path.parent.name}/{path.stem}'")
        if vector.get("level") != path.parent.parent.name:
            problems.append(f"{shown}: level is {vector.get('level')!r}, expected {path.parent.parent.name!r}")
        if path.parent.name not in COMPUTE:
            problems.append(f"{shown}: no executor for the area {path.parent.name!r}")
        if path.parent.name == "schema":
            referenced.add(str(vector["input"]["schema"]))
    return problems, referenced


def registry_problems(root: pathlib.Path) -> list[str]:
    """Problems in the registries: schema version, sorted and unique entries."""
    problems: list[str] = []
    for path in sorted((root / "registry").glob("*.yaml")):
        data = YAML(typ="safe").load(path.read_text("utf-8"))
        shown = f"registry/{path.name}"
        if data.get("schema_version") != "1.0":
            problems.append(f"{shown}: schema_version is 1.0")
        keys = [str(entry.get("code") or entry.get("name")) for entry in data.get("entries", [])]
        if not keys:
            problems.append(f"{shown}: no entries")
        if keys != sorted(keys):
            problems.append(f"{shown}: entries are not sorted")
        if len(set(keys)) != len(keys):
            problems.append(f"{shown}: an entry appears twice")
    return problems


def check(root: pathlib.Path) -> list[str]:
    """Every problem found in the protocol data under `root`."""
    vectors, referenced = vector_problems(root)
    problems = [*schema_problems(root, referenced), *vectors, *registry_problems(root)]
    report = run("connect", vectors=root / "vectors")
    problems.extend(f"vector {r.id}: {r.detail}" for r in report.results if r.status != "pass")
    return problems


def main() -> int:
    """Check the data of this checkout."""
    problems = check(data_dir())
    for problem in problems:
        print(problem, file=sys.stderr)
    if not problems:
        print("protocol data: ok")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
