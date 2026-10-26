"""SQLite access. One short-lived connection per use; WAL for concurrency."""
import sqlite3
from contextlib import contextmanager

from . import DB_SCHEMA, config

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(
  hash TEXT PRIMARY KEY, uid INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created INTEGER NOT NULL, expires INTEGER NOT NULL, last_seen INTEGER NOT NULL,
  kind TEXT NOT NULL, agent TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS notes(
  id INTEGER PRIMARY KEY, uid INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL, body TEXT NOT NULL, updated INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS notes_uid ON notes(uid, updated DESC);
CREATE TABLE IF NOT EXISTS prefs(
  uid INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS desktop(
  uid INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, kind TEXT NOT NULL,
  data TEXT NOT NULL, PRIMARY KEY(uid, kind));
CREATE TABLE IF NOT EXISTS app_kv(
  app TEXT NOT NULL, uid INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  key TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY(app, uid, key));
CREATE TABLE IF NOT EXISTS login_failures(
  key TEXT PRIMARY KEY, count INTEGER NOT NULL, locked_until INTEGER NOT NULL, updated INTEGER NOT NULL);
"""


@contextmanager
def connect():
    c = sqlite3.connect(config.DATA / "pios.db", timeout=10, isolation_level=None)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    try:
        yield c
    finally:
        c.close()


@contextmanager
def tx():
    """Connection inside an immediate transaction (commit/rollback automatic)."""
    with connect() as c:
        c.execute("BEGIN IMMEDIATE")
        try:
            yield c
        except BaseException:
            c.execute("ROLLBACK")
            raise
        else:
            c.execute("COMMIT")


# version -> SQL that upgrades from version-1. Version 1 is the baseline (SCHEMA, idempotent), so databases
# created by 0.1.x (user_version 0) are adopted. Add new steps here and bump DB_SCHEMA in pios/__init__.py.
MIGRATIONS: dict[int, str] = {
    # 2 (0.3.0): NOVA Shield - app permissions, tamper-evident audit log, upload quarantine, scan history, settings
    2: """
CREATE TABLE IF NOT EXISTS app_state(
  app TEXT PRIMARY KEY, origin TEXT NOT NULL, version TEXT NOT NULL, requested TEXT NOT NULL,
  first_seen INTEGER NOT NULL, updated INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS app_grants(
  app TEXT NOT NULL, perm TEXT NOT NULL, granted_by TEXT NOT NULL, time INTEGER NOT NULL, PRIMARY KEY(app, perm));
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, kind TEXT NOT NULL, severity TEXT NOT NULL, actor TEXT NOT NULL,
  ip TEXT NOT NULL, detail TEXT NOT NULL, prev TEXT NOT NULL, hash TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS audit_kind ON audit(kind, ts);
CREATE TABLE IF NOT EXISTS audit_anchor(id INTEGER PRIMARY KEY CHECK(id = 1), hash TEXT NOT NULL, upto INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS quarantine(
  id TEXT PRIMARY KEY, uid INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, dest_dir TEXT NOT NULL, name TEXT NOT NULL,
  size INTEGER NOT NULL, sha256 TEXT NOT NULL, detected_type TEXT NOT NULL, state TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '',
  detection TEXT NOT NULL DEFAULT '', created INTEGER NOT NULL, scanned INTEGER, origin TEXT NOT NULL DEFAULT 'upload');
CREATE INDEX IF NOT EXISTS quarantine_state ON quarantine(state);
CREATE TABLE IF NOT EXISTS scans(
  id INTEGER PRIMARY KEY, kind TEXT NOT NULL, state TEXT NOT NULL, started INTEGER NOT NULL, finished INTEGER,
  files INTEGER NOT NULL DEFAULT 0, bytes INTEGER NOT NULL DEFAULT 0, infected INTEGER NOT NULL DEFAULT 0,
  errors INTEGER NOT NULL DEFAULT 0, note TEXT NOT NULL DEFAULT '', uid INTEGER);
CREATE TABLE IF NOT EXISTS shield_settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
""",
}


class SchemaTooNew(RuntimeError):
    pass


def init():
    config.DATA.mkdir(parents=True, exist_ok=True, mode=0o700)
    with connect() as c:
        c.execute("PRAGMA journal_mode=WAL")
        have = c.execute("PRAGMA user_version").fetchone()[0]
        if have > DB_SCHEMA:
            # An older release must never run on a database a newer one has migrated: refuse to start so the
            # Update Manager's health check fails and the pre-update backup is restored.
            raise SchemaTooNew(f"Datenbank-Schema {have} ist neuer als von dieser Version unterstützt ({DB_SCHEMA})")
        c.executescript(SCHEMA)
        if have < 1:
            c.execute("PRAGMA user_version=1")
            have = 1
        for v in range(have + 1, DB_SCHEMA + 1):
            # one atomic script per step: schema change and version bump commit together
            c.executescript(f"BEGIN IMMEDIATE;\n{MIGRATIONS[v]}\nPRAGMA user_version={v};\nCOMMIT;")


def healthy() -> bool:
    try:
        with connect() as c:
            return c.execute("SELECT COUNT(*) FROM users").fetchone() is not None
    except Exception:
        return False
