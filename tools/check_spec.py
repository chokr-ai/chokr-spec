"""Check the protocol data as a whole. Exits 1 and lists every problem when any check fails.

- every schema is valid Draft 2020-12, has the `$id` its file name implies, rejects unknown properties, requires its
  version field and is used by at least one schema vector;
- every vector is valid JSON with a unique `id` and `level` that match its path, and an area that the reference checker
  can run;
- every registry has a schema version and sorted, unique entries;
- every trust area has a valid vector and, where it has a signed document, a tamper vector (CHK-TRU-14);
- `proto/service_plugin.proto` declares the package and every service of the plugin protocol;
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
# What each trust area must have at least one vector of. `tamper` is a signed document changed after it was signed.
TRUST_AREAS = {
    "credential": ("valid", "tamper"),
    "crypto": ("valid", "tamper"),
    "delegation": ("valid", "tamper"),
    "epoch": ("valid", "tamper"),
    "evidence": ("valid", "tamper"),
    "jws": ("valid", "tamper"),
    "keybinding": ("valid", "tamper"),
    "passport": ("valid", "tamper"),
    "pop": ("valid", "tamper"),
    "sdjwt": ("valid", "tamper"),
    "thumbprint": ("valid",),
    "vc": ("valid", "tamper"),
}
VECTOR_CLASSES = ("valid", "invalid", "tamper")
PROTO_PACKAGE = "chokr.service_plugin.v1"
PROTO_SERVICES = (
    "Plugin",
    "Guard",
    "CplFunction",
    "EvidenceVerifier",
    "ObligationHandler",
    "IsolationProvider",
    "EventImporter",
)


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


def trust_counts(root: pathlib.Path) -> dict[str, dict[str, int]]:
    """How many vectors of each class every trust area has."""
    counts: dict[str, dict[str, int]] = {}
    for path in sorted((root / "vectors" / "trust").glob("*/*.json")):
        try:
            kind = json.loads(path.read_text("utf-8")).get("class")
        except ValueError, AttributeError:
            continue
        area = counts.setdefault(path.parent.name, {})
        area[str(kind)] = area.get(str(kind), 0) + 1
    return counts


def trust_problems(root: pathlib.Path) -> list[str]:
    """Problems in the trust vectors: a class outside the three, an area the lint does not know, and an area that has
    no valid vector or no tamper vector."""
    problems: list[str] = []
    counts = trust_counts(root)
    for area, classes in sorted(counts.items()):
        if area not in TRUST_AREAS:
            problems.append(f"vectors/trust/{area}: not a known trust area")
        problems.extend(
            f"vectors/trust/{area}: class {kind!r} is not one of {', '.join(VECTOR_CLASSES)}"
            for kind in classes
            if kind not in VECTOR_CLASSES
        )
    for area, needed in TRUST_AREAS.items():
        problems.extend(
            f"vectors/trust/{area}: no {kind} vector" for kind in needed if counts.get(area, {}).get(kind, 0) == 0
        )
    return problems


def proto_problems(root: pathlib.Path) -> list[str]:
    """Problems in the plugin protocol: the file is there and names its package and every service."""
    path = root / "proto" / "service_plugin.proto"
    if not path.is_file():
        return ["proto/service_plugin.proto: missing"]
    text = path.read_text("utf-8")
    problems = []
    if 'syntax = "proto3";' not in text:
        problems.append("proto/service_plugin.proto: is not proto3")
    if f"package {PROTO_PACKAGE};" not in text:
        problems.append(f"proto/service_plugin.proto: package is not {PROTO_PACKAGE}")
    problems.extend(
        f"proto/service_plugin.proto: no service {name}" for name in PROTO_SERVICES if f"service {name} {{" not in text
    )
    return problems


def check(root: pathlib.Path) -> list[str]:
    """Every problem found in the protocol data under `root`."""
    vectors, referenced = vector_problems(root)
    problems = [
        *schema_problems(root, referenced),
        *vectors,
        *registry_problems(root),
        *trust_problems(root),
        *proto_problems(root),
    ]
    report = run("trust", vectors=root / "vectors")
    problems.extend(f"vector {r.id}: {r.detail}" for r in report.results if r.status != "pass")
    return problems


def main() -> int:
    """Check the data of this checkout."""
    problems = check(data_dir())
    for problem in problems:
        print(problem, file=sys.stderr)
    if not problems:
        for area, classes in sorted(trust_counts(data_dir()).items()):
            shown = ", ".join(f"{count} {kind}" for kind, count in sorted(classes.items()))
            print(f"trust/{area}: {sum(classes.values())} vectors ({shown})")
        print("protocol data: ok")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
