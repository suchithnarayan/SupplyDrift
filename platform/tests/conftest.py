"""Shared fixtures for the platform test suite.

All business logic lives in the ``Store`` class (``app.py``); ``server.py`` is the
FastAPI HTTP layer. ``test_store``/``test_pagination`` exercise the Store directly;
``test_fastapi`` exercises the HTTP contract via FastAPI's TestClient.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # platform/ on path
import app as appmod  # noqa: E402


@pytest.fixture(autouse=True)
def _auth_disabled_by_default(monkeypatch):
    """The suite runs unauthenticated by default (matches pre-auth behavior); the
    dedicated auth tests opt back in with monkeypatch.setenv(..., 'enabled')."""
    monkeypatch.setenv("SUPPLYDRIFT_AUTH", "disabled")


@pytest.fixture
def store(tmp_path):
    """A fresh Store on a temp DB, pre-loaded with demo data."""
    s = appmod.Store(tmp_path / "test.db")
    s.ingest(appmod.demo_payload())
    return s


@pytest.fixture
def empty_store(tmp_path):
    return appmod.Store(tmp_path / "empty.db")


@pytest.fixture
def fastapi_client(tmp_path):
    """FastAPI TestClient over a demo-loaded temp Store. Yields (client, store)."""
    from fastapi.testclient import TestClient

    import server

    s = appmod.Store(tmp_path / "fa.db")
    s.ingest(appmod.demo_payload())
    with TestClient(server.create_app(s)) as client:
        yield client, s
