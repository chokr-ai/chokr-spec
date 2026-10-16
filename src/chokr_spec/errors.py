"""The error type of the reference checker."""

from __future__ import annotations


class SpecError(Exception):
    """A value the protocol rejects. `code` is a stable upper-case name."""

    code = "SCHEMA_INVALID"

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        if code is not None:
            self.code = code


class CanonicalizationError(SpecError):
    """A value cannot be written as canonical JSON."""

    code = "CANONICALIZATION_ERROR"
