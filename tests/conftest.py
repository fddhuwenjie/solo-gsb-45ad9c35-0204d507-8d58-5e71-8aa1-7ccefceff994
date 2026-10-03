"""Shared pytest fixtures."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("SUBNET_DB_PATH", str(db_path))

    from app import db as db_module

    monkeypatch.setattr(db_module, "DB_PATH", str(db_path))
    db_module.init_db()

    from app.main import app

    with TestClient(app) as c:
        yield c
