"""CHOKR protocol data: JSON Schemas, registries and conformance vectors, with a reference checker.

`data_dir()` locates the data. `run()` checks the vectors with the reference checker in this package, and any other
implementation can reproduce the same vectors to show that it speaks the protocol.
"""

from __future__ import annotations

from pathlib import Path

__version__ = "0.0.3"
PROTOCOL_VERSION = "1.0"


def data_dir() -> Path:
    """The folder that holds `schemas/`, `registry/` and `vectors/`: the checkout itself or the installed data."""
    here = Path(__file__).resolve().parent
    checkout = here.parent.parent
    return checkout if (checkout / "schemas").is_dir() else here / "data"
