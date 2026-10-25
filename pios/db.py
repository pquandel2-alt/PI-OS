"""SQLite access. One short-lived connection per use; WAL for concurrency."""
import sqlite3
from contextlib import contextmanager

from . import config

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


def init():
    config.DATA.mkdir(parents=True, exist_ok=True, mode=0o700)
    with connect() as c:
        c.execute("PRAGMA journal_mode=WAL")
        c.executescript(SCHEMA)
