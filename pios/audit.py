"""Tamper-evident security audit log.

Every entry carries the hash of its predecessor (a hash chain), so removing or editing an old entry is detectable by
`verify()`. There is deliberately no API to modify or delete entries; normal users cannot read the log at all. Entries
are also written to the journal (a second, root-owned copy outside this process).
Never log secrets: values for sensitive keys are dropped, everything is truncated.
"""
import hashlib
import json
import logging
import threading
import time

from . import db

log = logging.getLogger("pios.audit")
MAX_ROWS = 20_000
KEEP_ROWS = 18_000
MAX_AGE_DAYS = 365
MAX_DETAIL = 400
SENSITIVE = ("password", "passwd", "secret", "token", "cookie", "authorization", "session", "key", "code", "hash")
_lock = threading.Lock()
_last_prune = 0.0

SEVERITIES = ("info", "notice", "warning", "critical")


def _clean(detail: dict) -> dict:
    out = {}
    for k, v in detail.items():
        if any(s in k.lower() for s in SENSITIVE):
            continue
        out[k] = v if isinstance(v, (int, float, bool)) or v is None else str(v)[:MAX_DETAIL]
    return out


def _digest(prev: str, ts: int, kind: str, sev: str, actor: str, ip: str, detail: str) -> str:
    return hashlib.sha256("\x1f".join((prev, str(ts), kind, sev, actor, ip, detail)).encode()).hexdigest()


def event(kind: str, severity: str = "info", actor: str = "", ip: str = "", **detail) -> int | None:
    """Append an entry. Never raises: a logging problem must not break the operation being logged."""
    global _last_prune
    if severity not in SEVERITIES:
        severity = "info"
    ts = int(time.time())
    det = json.dumps(_clean(detail), sort_keys=True, ensure_ascii=False)
    try:
        with _lock, db.tx() as c:
            row = c.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
            prev = row["hash"] if row else (c.execute("SELECT hash FROM audit_anchor").fetchone() or {"hash": "genesis"})["hash"]
            h = _digest(prev, ts, kind, severity, actor[:80], ip[:64], det)
            cur = c.execute("INSERT INTO audit(ts,kind,severity,actor,ip,detail,prev,hash) VALUES(?,?,?,?,?,?,?,?)",
                            (ts, kind, severity, actor[:80], ip[:64], det, prev, h))
            rid = cur.lastrowid
            if time.time() - _last_prune > 600:
                _last_prune = time.time()
                _prune(c)
        log.info(json.dumps({"audit": kind, "severity": severity, "actor": actor, "ip": ip, **json.loads(det)}, ensure_ascii=False))
        return rid
    except Exception:                                                    # noqa: BLE001
        log.exception("audit write failed for %s", kind)
        return None


def _prune(c):
    """Retention: at most MAX_ROWS rows and MAX_AGE_DAYS days; the hash of the last removed row anchors the chain."""
    cutoff = int(time.time()) - MAX_AGE_DAYS * 86400
    n = c.execute("SELECT COUNT(*) FROM audit").fetchone()[0]
    drop_to = None
    if n > MAX_ROWS:
        drop_to = c.execute("SELECT id FROM audit ORDER BY id DESC LIMIT 1 OFFSET ?", (KEEP_ROWS,)).fetchone()["id"]
    old = c.execute("SELECT MAX(id) AS m FROM audit WHERE ts<?", (cutoff,)).fetchone()["m"]
    if old and (drop_to is None or old > drop_to):
        drop_to = old
    if drop_to:
        last = c.execute("SELECT id,hash FROM audit WHERE id<=? ORDER BY id DESC LIMIT 1", (drop_to,)).fetchone()
        if last:
            c.execute("INSERT INTO audit_anchor(id,hash,upto) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET hash=excluded.hash, upto=excluded.upto",
                      (last["hash"], last["id"]))
            c.execute("DELETE FROM audit WHERE id<=?", (last["id"],))


def verify() -> dict:
    """Walk the chain. Returns {ok, entries, first_bad_id, reason}."""
    with db.connect() as c:
        anchor = c.execute("SELECT hash,upto FROM audit_anchor").fetchone()
        expected = anchor["hash"] if anchor else "genesis"
        n = 0
        for r in c.execute("SELECT * FROM audit ORDER BY id"):
            n += 1
            if r["prev"] != expected:
                return {"ok": False, "entries": n, "first_bad_id": r["id"], "reason": "Kette unterbrochen (Eintrag fehlt oder wurde verändert)"}
            if _digest(r["prev"], r["ts"], r["kind"], r["severity"], r["actor"], r["ip"], r["detail"]) != r["hash"]:
                return {"ok": False, "entries": n, "first_bad_id": r["id"], "reason": "Eintrag wurde verändert"}
            expected = r["hash"]
    return {"ok": True, "entries": n, "first_bad_id": None, "reason": ""}


def recent(limit=200, kind=None, severity=None, since=0) -> list[dict]:
    sql, args = "SELECT id,ts,kind,severity,actor,ip,detail FROM audit WHERE ts>=?", [since]
    if kind:
        sql += " AND kind LIKE ?"; args.append(kind.replace("%", "") + "%")
    if severity:
        sql += " AND severity=?"; args.append(severity)
    with db.connect() as c:
        rows = c.execute(sql + " ORDER BY id DESC LIMIT ?", (*args, max(1, min(limit, 1000)))).fetchall()
    return [{**dict(r), "detail": json.loads(r["detail"])} for r in rows]


def count(kind_prefix: str, since: int) -> int:
    with db.connect() as c:
        return c.execute("SELECT COUNT(*) FROM audit WHERE kind LIKE ? AND ts>=?", (kind_prefix + "%", since)).fetchone()[0]
