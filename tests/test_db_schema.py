import sqlite3

import pytest


def _reload(monkeypatch, tmp_path):
    import importlib, sys
    monkeypatch.setenv("PIOS_DATA", str(tmp_path))
    for m in [m for m in sys.modules if m == "pios" or m.startswith("pios.")]:
        del sys.modules[m]
    return importlib.import_module("pios.db")


def test_fresh_database_gets_current_schema_version(tmp_path, monkeypatch):
    db = _reload(monkeypatch, tmp_path)
    db.init()
    from pios import DB_SCHEMA
    assert sqlite3.connect(tmp_path / "pios.db").execute("PRAGMA user_version").fetchone()[0] == DB_SCHEMA
    assert db.healthy()


def test_database_from_0_1_x_is_adopted_with_data_intact(tmp_path, monkeypatch):
    db = _reload(monkeypatch, tmp_path)
    c = sqlite3.connect(tmp_path / "pios.db")
    c.executescript(db.SCHEMA)                         # exactly what 0.1.x created: tables, user_version 0
    c.execute("INSERT INTO users(username,password,role,created) VALUES('old','x','admin',1)"); c.commit(); c.close()
    db.init()
    c = sqlite3.connect(tmp_path / "pios.db")
    from pios import DB_SCHEMA
    assert c.execute("PRAGMA user_version").fetchone()[0] == DB_SCHEMA
    assert c.execute("SELECT username FROM users").fetchone()[0] == "old"
    assert c.execute("SELECT name FROM sqlite_master WHERE name='audit'").fetchone(), "v2 tables created by the migration"


def test_newer_database_is_refused(tmp_path, monkeypatch):
    c = sqlite3.connect(tmp_path / "pios.db"); c.execute("PRAGMA user_version=99"); c.commit(); c.close()
    db = _reload(monkeypatch, tmp_path)
    with pytest.raises(db.SchemaTooNew):
        db.init()
    assert sqlite3.connect(tmp_path / "pios.db").execute("PRAGMA user_version").fetchone()[0] == 99, "untouched"
