"""Canonical JSON and digests: the bytes that every hash and signature of the protocol covers."""

from __future__ import annotations

import hashlib
from typing import Any

import rfc8785

from chokr_spec.errors import CanonicalizationError

MAX_DEPTH = 200


def _check_depth(value: Any, max_depth: int) -> None:
    """Walk the value without recursion, so a deeply nested input cannot exhaust the stack."""
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        if isinstance(current, dict):
            children: Any = current.values()
        elif isinstance(current, list | tuple):
            children = current
        else:
            continue
        if depth > max_depth:
            raise CanonicalizationError(f"nesting exceeds {max_depth} levels")
        stack.extend((child, depth + 1) for child in children)


def canonicalize(value: Any, *, max_depth: int = MAX_DEPTH) -> bytes:
    """The canonical JSON bytes of `value` (RFC 8785). Nesting is limited to `max_depth`, at most 200 levels."""
    if not 1 <= max_depth <= MAX_DEPTH:
        raise ValueError(f"max_depth is between 1 and {MAX_DEPTH}")
    _check_depth(value, max_depth)
    try:
        return rfc8785.dumps(value)
    except rfc8785.CanonicalizationError as exc:
        raise CanonicalizationError(str(exc)) from exc
    except (TypeError, ValueError, RecursionError) as exc:
        raise CanonicalizationError(type(exc).__name__) from exc


def digest_bytes(data: bytes) -> str:
    """`sha256:` followed by the hex digest of `data`."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


def digest_object(value: Any, *, max_depth: int = MAX_DEPTH) -> str:
    """The digest of the canonical JSON of `value`."""
    return digest_bytes(canonicalize(value, max_depth=max_depth))
