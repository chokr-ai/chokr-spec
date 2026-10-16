"""Shared helpers for the tests."""

import shutil
from pathlib import Path

import pytest

from chokr_spec import data_dir


@pytest.fixture
def data_copy(tmp_path: Path) -> Path:
    """A writable copy of the protocol data, so a test can break it."""
    root = tmp_path / "data"
    for name in ("schemas", "registry", "vectors"):
        shutil.copytree(data_dir() / name, root / name)
    return root
