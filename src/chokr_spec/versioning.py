"""Version compatibility: a reader that supports `1.m` accepts `1.0` up to `1.m` and refuses anything else."""

from __future__ import annotations

import re
from typing import Any

from chokr_spec import PROTOCOL_VERSION
from chokr_spec.errors import SpecError

_VERSION = re.compile(r"(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})")


def parse_version(value: Any) -> tuple[int, int]:
    """The `(major, minor)` of a `MAJOR.MINOR` string. Anything else is an error."""
    if not isinstance(value, str) or (match := _VERSION.fullmatch(value)) is None:
        raise SpecError("schema_version is MAJOR.MINOR")
    return int(match.group(1)), int(match.group(2))


def check_schema_version(value: Any, *, supported: str = PROTOCOL_VERSION, name: str = "object") -> str:
    """Return `value` when this reader supports it. A missing or malformed value, another major version or a higher
    minor than `supported` raises `SpecError`, so a newer field is never ignored by accident."""
    if value is None:
        raise SpecError(f"{name}: schema_version is required")
    major, minor = parse_version(value)
    supported_major, supported_minor = parse_version(supported)
    if major != supported_major or minor > supported_minor:
        raise SpecError(
            f"{name}: schema_version {value} is not supported (this reader supports {supported_major}.0 to {supported})"
        )
    return str(value)
