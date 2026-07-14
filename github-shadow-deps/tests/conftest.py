"""Shared pytest fixtures."""
from __future__ import annotations

from pathlib import Path

import pytest

from github_inventory.config import Config
from github_inventory.discovery import FileTarget


FIXTURES_DIR = Path(__file__).parent / "fixtures"


def make_target(path: Path, rel_path: str, file_type: str) -> FileTarget:
    return FileTarget(path=path, rel_path=rel_path, file_type=file_type)


def make_inline_target(content: str, file_type: str, tmp_path: Path, name: str = "test.txt") -> FileTarget:
    """Write content to a temp file and return a FileTarget pointing at it."""
    p = tmp_path / name
    p.write_text(content)
    return FileTarget(path=p, rel_path=name, file_type=file_type)


@pytest.fixture
def default_config() -> Config:
    return Config()
