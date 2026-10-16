"""Run the conformance vectors and report.

The report is `{schema_version, spec_version, implementation, version, level, results, passed, failed, skipped}`.
A run is `ok` only when nothing failed, nothing was skipped and at least one vector passed, so an empty folder of
vectors can never pass.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from chokr_spec import __version__, data_dir
from chokr_spec.executors import COMPUTE, EXPECTED_KEYS, Context

LEVELS = ("core", "connect")
REPORT_SCHEMA = "1.0"
IMPLEMENTATION = "chokr-spec reference checker"


@dataclass
class Result:
    """The outcome of one vector: `pass` or `fail`, with a short detail for a failure."""

    id: str
    status: str
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """The result as JSON-compatible data."""
        out: dict[str, Any] = {"id": self.id, "status": self.status}
        if self.detail:
            out["detail"] = self.detail
        return out


@dataclass
class Report:
    """All results of a run for one level."""

    level: str
    implementation: str = IMPLEMENTATION
    version: str = __version__
    spec_version: str = __version__
    results: list[Result] = field(default_factory=list)

    @property
    def passed(self) -> int:
        """How many vectors passed."""
        return sum(result.status == "pass" for result in self.results)

    @property
    def failed(self) -> int:
        """How many vectors failed."""
        return sum(result.status == "fail" for result in self.results)

    @property
    def skipped(self) -> int:
        """How many vectors were skipped."""
        return sum(result.status == "skip" for result in self.results)

    @property
    def ok(self) -> bool:
        """True when nothing failed or was skipped and at least one vector passed."""
        return self.failed == 0 and self.skipped == 0 and self.passed > 0

    def to_dict(self) -> dict[str, Any]:
        """The report as JSON-compatible data."""
        return {
            "schema_version": REPORT_SCHEMA,
            "spec_version": self.spec_version,
            "implementation": self.implementation,
            "version": self.version,
            "level": self.level,
            "results": [result.to_dict() for result in self.results],
            "passed": self.passed,
            "failed": self.failed,
            "skipped": self.skipped,
        }


def _subset(expected: Any, actual: Any) -> bool:
    """True when every key of `expected` is present in `actual` with the same value, at every depth.

    Keys that only `actual` has are ignored. A boolean equals only a boolean, so `true` never equals `1`.
    """
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(k in actual and _subset(v, actual[k]) for k, v in expected.items())
    if isinstance(expected, bool) or isinstance(actual, bool):
        return type(expected) is type(actual) and expected == actual
    return bool(expected == actual)


def _execute(path: Path, area: str, context: Context) -> Result:
    vector_id = f"{path.parent.parent.name}/{area}/{path.stem}"
    try:
        vector = json.loads(path.read_text("utf-8"))
        vector_id = str(vector.get("id") or vector_id)
        compute = COMPUTE.get(area)
        if compute is None:
            return Result(vector_id, "fail", f"no executor for the area {area!r}")
        actual = compute(vector, context)
        keys = EXPECTED_KEYS.get(area)
        expected = {key: vector[key] for key in keys if key in vector} if keys else vector["expected"]
        if not expected:
            return Result(vector_id, "fail", "the vector has no expected value")
        if _subset(expected, actual):
            return Result(vector_id, "pass")
        shown = json.dumps(expected, sort_keys=True)[:300], json.dumps(actual, sort_keys=True, default=str)[:300]
        return Result(vector_id, "fail", f"expected {shown[0]}, got {shown[1]}")
    except Exception as exc:  # a vector that cannot run is a failure, whatever the cause
        return Result(vector_id, "fail", type(exc).__name__)


def run(level: str = "core", *, vectors: Path | None = None) -> Report:
    """Run every vector up to `level` and return the report. `vectors` defaults to the packaged vectors."""
    if level not in LEVELS:
        raise ValueError(f"level is one of {', '.join(LEVELS)}")
    data = data_dir()
    root = vectors if vectors is not None else data / "vectors"
    context = Context(schemas=data / "schemas")
    report = Report(level=level)
    for name in LEVELS[: LEVELS.index(level) + 1]:
        areas = sorted(p for p in (root / name).glob("*") if p.is_dir()) if (root / name).is_dir() else []
        if not areas:
            report.results.append(Result(name, "fail", f"no vectors under {root / name}"))
            continue
        for area_dir in areas:
            files = sorted(area_dir.glob("*.json"))
            if not files:
                report.results.append(Result(f"{name}/{area_dir.name}", "fail", "no vectors in this area"))
            report.results.extend(_execute(path, area_dir.name, context) for path in files)
    return report
