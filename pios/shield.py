"""NOVA Shield API (admin only): security status, audit log, app permissions, firewall, malware protection, OS updates."""
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

import asyncio
import os
import time

from . import apps, audit, config, db, firewall, hardening, malware, security, sysops, updates
from .security import admin_user

router = APIRouter(prefix="/api/shield")


# ---- audit log (read-only) -----------------------------------------------------------------------------
@router.get("/audit")
def audit_list(limit: int = Query(200, ge=1, le=1000), kind: str | None = Query(None, max_length=40),
               severity: Literal["info", "notice", "warning", "critical"] | None = None, u=Depends(admin_user)):
    return {"entries": audit.recent(limit, kind=kind, severity=severity), "integrity": audit.verify()}


@router.get("/audit/verify")
def audit_verify(u=Depends(admin_user)):
    return audit.verify()


# ---- app permissions -----------------------------------------------------------------------------------
class GrantBody(BaseModel):
    permission: str = Field(max_length=40)
    allow: bool


@router.get("/apps")
def apps_overview(u=Depends(admin_user)):
    return {"apps": apps.app_overview(), "permissions": apps.PERMISSIONS}


@router.put("/apps/{app_id}/grants")
def set_grant(app_id: str, b: GrantBody, request: Request, u=Depends(admin_user)):
    m = apps.registry.apps.get(app_id)
    if not m or m.kind != "sandboxed":
        raise HTTPException(404, "App nicht gefunden")
    if b.permission not in m.permissions:
        raise HTTPException(400, "Die App hat diese Berechtigung nicht angefragt")
    with db.tx() as c:
        if b.allow:
            c.execute("INSERT INTO app_grants VALUES(?,?,?,?) ON CONFLICT(app,perm) DO UPDATE SET granted_by=excluded.granted_by, time=excluded.time",
                      (app_id, b.permission, u["username"], int(time.time())))
        else:
            c.execute("DELETE FROM app_grants WHERE app=? AND perm=?", (app_id, b.permission))
    audit.event("app.permission_changed", "notice", actor=u["username"], ip=security.client_ip(request),
                app=app_id, permission=b.permission, allowed=b.allow)
    return {"app": next(a for a in apps.app_overview() if a["id"] == app_id)}


# ---- malware protection ----------------------------------------------------------------------------------------
class MalwareSettings(BaseModel):
    enabled: bool | None = None
    policy: Literal["fail_closed", "allow_unscanned"] | None = None
    schedule: Literal["weekly", "off"] | None = None
    on_demand: bool | None = None
    max_scan_mb: int | None = Field(default=None, ge=1, le=4096)


@router.get("/malware")
def malware_status(u=Depends(admin_user)):
    return malware.scanner_status()


@router.put("/malware/settings")
def malware_settings(b: MalwareSettings, request: Request, u=Depends(admin_user)):
    if malware.env_off():
        raise HTTPException(409, "Der Virenschutz ist durch die Umgebung (PIOS_MALWARE=off) abgeschaltet")
    changes = {}
    for key, val in (("malware.enabled", None if b.enabled is None else ("1" if b.enabled else "0")), ("malware.policy", b.policy),
                     ("malware.schedule", b.schedule), ("malware.on_demand", None if b.on_demand is None else ("1" if b.on_demand else "0")),
                     ("malware.max_scan_mb", None if b.max_scan_mb is None else str(b.max_scan_mb))):
        if val is not None:
            malware.set_setting(key, val)
            changes[key.split(".", 1)[1]] = val
    sev = "warning" if changes.get("enabled") == "0" or changes.get("policy") == "allow_unscanned" else "notice"
    audit.event("malware.settings_changed", sev, actor=u["username"], ip=security.client_ip(request), **changes)
    return malware.scanner_status()


@router.get("/quarantine")
def quarantine_list(u=Depends(admin_user)):
    with db.connect() as c:
        names = {r["id"]: r["username"] for r in c.execute("SELECT id,username FROM users")}
    return [{**i, "user": names.get(i["uid"], "?")} for i in malware.list_items()]


@router.delete("/quarantine/{qid}")
def quarantine_delete(qid: str, request: Request, u=Depends(security.current_user)):
    row = malware.get_item(qid) if len(qid) == 32 and qid.isalnum() else None
    if not row or (u["role"] != "admin" and row["uid"] != u["id"]):
        raise HTTPException(404, "Nicht gefunden")
    if row["state"] in ("released", "released_unscanned"):
        raise HTTPException(409, "Die Datei wurde bereits freigegeben; lösche sie in NOVA Files")
    malware.delete_item(qid)
    audit.event("malware.quarantine_deleted", "notice", actor=u["username"], ip=security.client_ip(request), file=row["name"], state=row["state"])
    return {"ok": True}


@router.post("/quarantine/{qid}/rescan")
def quarantine_rescan(qid: str, u=Depends(admin_user)):
    row = malware.get_item(qid) if len(qid) == 32 and qid.isalnum() else None
    if not row or row["state"] not in ("held", "error", "pending"):
        raise HTTPException(409, "Nur wartende oder fehlgeschlagene Prüfungen können wiederholt werden")
    malware.set_state(qid, "pending", "Erneute Prüfung angefordert")
    return {"ok": True}


class ScanBody(BaseModel):
    scope: Literal["all"] = "all"


@router.post("/scans")
def scan_start(b: ScanBody, request: Request, u=Depends(admin_user)):
    if not malware.enabled():
        raise HTTPException(409, "Virenschutz ist deaktiviert")
    try:
        jid = malware.start_scan("manual")
    except RuntimeError as e:
        raise HTTPException(409, str(e)) from None
    audit.event("malware.scan_started", "info", actor=u["username"], ip=security.client_ip(request), scan=jid)
    return {"id": jid}


@router.get("/scans")
def scan_list(u=Depends(admin_user)):
    with db.connect() as c:
        return {"scans": [dict(r) for r in c.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 30")], "running": malware.scan_job_running()}


@router.post("/scans/{jid}/cancel")
def scan_cancel(jid: int, u=Depends(admin_user)):
    if not malware.cancel_scan(jid):
        raise HTTPException(404, "Kein laufender Scan mit dieser ID")
    audit.event("malware.scan_cancelled", "notice", actor=u["username"], scan=jid)
    return {"ok": True}


@router.post("/signatures/update")
def signatures_update(request: Request, u=Depends(admin_user)):
    try:
        sysops.call("signatures.update", timeout=15)
    except sysops.Unavailable:
        raise HTTPException(503, "Der System-Dienst ist nicht erreichbar (nur im PiOS-Image verfügbar)") from None
    except sysops.OpError as e:
        raise HTTPException(409, str(e)) from None
    audit.event("malware.signature_update_requested", "info", actor=u["username"], ip=security.client_ip(request))
    return {"ok": True}


async def malware_loop():
    """Background: process the quarantine queue, manage clamd on demand, start the weekly scan."""
    await asyncio.sleep(5)
    while True:
        try:
            await asyncio.to_thread(malware.manager.tick)
            await asyncio.to_thread(malware.maybe_scheduled_scan)
        except Exception:                                            # noqa: BLE001
            import logging
            logging.getLogger("pios.shield").exception("malware loop")
        await asyncio.sleep(3)


# ---- firewall ---------------------------------------------------------------------------------------------------
class FwBody(BaseModel):
    model_config = {"extra": "forbid"}
    web_scope: Literal["lan", "custom"] = "lan"
    web_cidrs: list[str] = Field(default_factory=list, max_length=16)
    ssh: bool = False
    mdns: bool = True
    ping: bool = True


def _fw(method, args=None, timeout=30):
    try:
        return firewall.call(method, args, timeout)
    except firewall.Unavailable:
        raise HTTPException(503, "Der Firewall-Dienst ist nicht erreichbar (nur im PiOS-Image verfügbar)") from None
    except firewall.FwError as e:
        raise HTTPException({"pending": 409, "nothing_pending": 409, "forbidden": 502}.get(e.code, 400), str(e)) from None


@router.get("/firewall")
def firewall_status(u=Depends(admin_user)):
    return _fw("status", timeout=10)


@router.post("/firewall/preview")
def firewall_preview(b: FwBody, u=Depends(admin_user)):
    return _fw("preview", {"config": b.model_dump()})


@router.post("/firewall/apply")
def firewall_apply(b: FwBody, request: Request, u=Depends(admin_user)):
    audit.event("firewall.change_applied", "warning", actor=u["username"], ip=security.client_ip(request), **{k: str(v) for k, v in b.model_dump().items()})
    return _fw("apply", {"config": b.model_dump()})


@router.post("/firewall/confirm")
def firewall_confirm(request: Request, u=Depends(admin_user)):
    r = _fw("confirm")
    audit.event("firewall.change_confirmed", "notice", actor=u["username"], ip=security.client_ip(request))
    return r


@router.post("/firewall/revert")
def firewall_revert(request: Request, u=Depends(admin_user)):
    r = _fw("revert")
    audit.event("firewall.reverted", "notice", actor=u["username"], ip=security.client_ip(request))
    return r


# ---- OS (Debian) security updates ----------------------------------------------------------------------------------
def _ops(method, args=None, timeout=30):
    try:
        return sysops.call(method, args, timeout)
    except sysops.Unavailable:
        raise HTTPException(503, "Der System-Dienst ist nicht erreichbar (nur im PiOS-Image verfügbar)") from None
    except sysops.OpError as e:
        raise HTTPException(409 if e.code == "busy" else 400, str(e)) from None


class OsConfig(BaseModel):
    auto_security: bool


@router.get("/os")
def os_status(u=Depends(admin_user)):
    return _ops("os.status", timeout=10)


@router.post("/os/check")
def os_check(request: Request, u=Depends(admin_user)):
    audit.event("os.check_requested", "info", actor=u["username"], ip=security.client_ip(request))
    return _ops("os.check")


@router.post("/os/upgrade")
def os_upgrade(request: Request, u=Depends(admin_user)):
    audit.event("os.security_upgrade_requested", "notice", actor=u["username"], ip=security.client_ip(request))
    return _ops("os.upgrade")


@router.put("/os/config")
def os_config(b: OsConfig, request: Request, u=Depends(admin_user)):
    audit.event("os.config_changed", "notice", actor=u["username"], ip=security.client_ip(request), auto_security=b.auto_security)
    return _ops("os.config", {"auto_security": b.auto_security})


# ---- overall security status -----------------------------------------------------------------------------------------
SEVERITY = {"ok": 0, "info": 0, "unknown": 1, "limited": 2, "attention": 3, "critical": 4}
VERDICT = {0: ("protected", "Geschützt"), 1: ("unknown", "Status unbekannt"), 2: ("limited", "Eingeschränkt geschützt"),
           3: ("attention", "Aufmerksamkeit erforderlich"), 4: ("critical", "Kritisches Problem")}


def chk(cid, title, level, detail, **extra):
    return {"id": cid, "title": title, "level": level, "detail": detail, "checked_at": int(time.time()), **extra}


def check_firewall():
    try:
        st = firewall.call("status", timeout=8)
    except firewall.Unavailable:
        return chk("firewall", "Firewall", "unknown", "Der Firewall-Dienst antwortet nicht. Es kann nicht geprüft werden, ob der Schutz aktiv ist.")
    except firewall.FwError as e:
        return chk("firewall", "Firewall", "unknown", f"Status nicht lesbar: {e}")
    if not st["active"]:
        return chk("firewall", "Firewall", "critical", "Die PiOS-Firewall ist nicht aktiv oder weicht von der Konfiguration ab: " + "; ".join(st["problems"]), data=st)
    if st.get("pending"):
        return chk("firewall", "Firewall", "attention", f"Eine Änderung wartet auf Bestätigung ({st['pending']['seconds_left']} s bis zur automatischen Rücknahme).", data=st)
    ports = ", ".join(f"{p}/tcp" for p in st["expected_ports"]["tcp"])
    scope = "lokales Netz" if st["config"]["web_scope"] == "lan" else "ausgewählte Netze"
    lvl = "limited" if st["config"]["ssh"] else "ok"
    return chk("firewall", "Firewall", lvl, f"Aktiv: eingehend gesperrt außer {ports} aus dem {scope}." + (" SSH ist freigegeben." if st["config"]["ssh"] else ""), data=st)


def check_malware():
    st = malware.scanner_status()
    sig = st["signatures"]
    if st["disabled_by_env"]:
        return chk("malware", "Virenschutz", "limited", "Der Virenschutz ist durch die Umgebung abgeschaltet (Entwicklungsmodus).", data=st)
    if not st["enabled"]:
        return chk("malware", "Virenschutz", "limited", "Der Virenschutz ist deaktiviert. Uploads werden nicht geprüft.", data=st)
    if not st["installed"]:
        return chk("malware", "Virenschutz", "limited", "ClamAV ist nicht installiert. Uploads bleiben gesperrt (fail-closed).", data=st)
    if not sig["present"]:
        return chk("malware", "Virenschutz", "limited", "Es sind noch keine Virensignaturen geladen. Uploads bleiben gesperrt, bis der erste Download abgeschlossen ist.", data=st)
    age = sig.get("age_days", 0)
    if age > 30:
        return chk("malware", "Virenschutz", "attention", f"Die Virensignaturen sind {age:.0f} Tage alt. Bitte aktualisieren (Internetverbindung?).", data=st)
    if age > 7:
        return chk("malware", "Virenschutz", "limited", f"Die Virensignaturen sind {age:.0f} Tage alt.", data=st)
    if st["quarantine"].get("infected"):
        return chk("malware", "Virenschutz", "attention", f"{st['quarantine']['infected']} erkannte Bedrohung(en) in Quarantäne. Bitte prüfen und löschen.", data=st)
    last = st["last_scan"]
    if not last:
        return chk("malware", "Virenschutz", "limited", "Aktiv, aber es wurde noch nie ein Scan der Benutzerdateien durchgeführt.", data=st)
    if time.time() - (last["finished"] or last["started"]) > 14 * 86400:
        return chk("malware", "Virenschutz", "limited", "Der letzte vollständige Scan liegt mehr als 14 Tage zurück.", data=st)
    return chk("malware", "Virenschutz", "ok", f"Aktiv (Signaturen {age:.0f} Tage alt, Scan on-demand), Policy: {st['policy']}.", data=st)


def check_sandbox():
    problems, n = [], 0
    for m in apps.registry.apps.values():
        if m.kind != "sandboxed":
            continue
        n += 1
        try:
            r = apps.app_asset(m.id, "")
        except HTTPException:
            problems.append(f"{m.name}: Startdatei nicht auslieferbar"); continue
        csp = r.headers.get("content-security-policy", "")
        if "sandbox allow-scripts" not in csp or "connect-src 'none'" not in csp or "allow-same-origin" in csp:
            problems.append(f"{m.name}: Sandbox-Header unvollständig")
    if apps.registry.errors:
        problems.append("Ungültige App-Manifeste: " + ", ".join(apps.registry.errors))
    page = hardening.DEFAULT_CSP
    if "script-src 'self'" not in page or "frame-ancestors 'none'" not in page or "unsafe-inline" in page or "unsafe-eval" in page:
        problems.append("Content-Security-Policy der Oberfläche ist zu offen")
    if problems:
        return chk("sandbox", "App-Sandbox", "critical", "; ".join(problems))
    return chk("sandbox", "App-Sandbox", "ok", f"{n} App(s) laufen in einer isolierten iframe-Sandbox ohne Netzwerkzugriff; Berechtigungen werden serverseitig geprüft.")


def check_hardening():
    """Self-attestation of this very process: capabilities, no_new_privs, seccomp."""
    try:
        text = open("/proc/self/status").read()
    except OSError:
        return chk("service", "Dienst-Härtung", "unknown", "Prozessstatus nicht lesbar.")
    def field(name):
        for line in text.splitlines():
            if line.startswith(name + ":"):
                return line.split(":", 1)[1].strip()
    uid = int(field("Uid").split()[0])
    nnp, seccomp = field("NoNewPrivs"), field("Seccomp")
    cap_eff = int(field("CapEff"), 16)
    problems = []
    if uid == 0:
        problems.append("Der Webserver läuft als root")
    if nnp != "1":
        problems.append("NoNewPrivileges ist nicht aktiv")
    if seccomp != "2":
        problems.append("Kein Systemaufruf-Filter (seccomp) aktiv")
    if cap_eff & ~(1 << 10):
        problems.append("Der Webserver besitzt mehr als CAP_NET_BIND_SERVICE")
    if problems:
        sandboxed = nnp == "1" or seccomp == "2"
        return chk("service", "Dienst-Härtung", "critical" if (uid == 0 or sandboxed) else "limited", "; ".join(problems) + ("" if sandboxed else " (kein systemd-Dienst? Entwicklungsmodus)"))
    return chk("service", "Dienst-Härtung", "ok", "Webserver läuft unprivilegiert mit NoNewPrivileges, seccomp-Filter und nur CAP_NET_BIND_SERVICE.")


def check_ota():
    try:
        st = updates.call("status", None, 8)
    except updates.Unavailable:
        return chk("ota", "PiOS-Updates (signiert)", "unknown", "Der Update-Dienst antwortet nicht.")
    except HTTPException:
        return chk("ota", "PiOS-Updates (signiert)", "unknown", "Update-Status nicht lesbar.")
    rej = st.get("rejected") or {}
    if rej:
        return chk("ota", "PiOS-Updates (signiert)", "attention", f"{len(rej)} Release(s) mit ungültiger Signatur abgelehnt: " + ", ".join(sorted(rej)), data=st)
    job = st.get("job") or {}
    if job.get("state") in ("failed", "failed_critical", "rolled_back"):
        return chk("ota", "PiOS-Updates (signiert)", "attention", f"Das letzte Update ist fehlgeschlagen ({job.get('error') or job['state']}).", data=st)
    if not st.get("last_success"):
        return chk("ota", "PiOS-Updates (signiert)", "unknown", "Es wurde noch nicht erfolgreich nach Updates gesucht." + (f" Letzter Fehler: {st['last_error']}" if st.get("last_error") else ""), data=st)
    age = (time.time() - st["last_success"]) / 86400
    av = st.get("available")
    if av and av.get("compatible"):
        return chk("ota", "PiOS-Updates (signiert)", "attention", f"PiOS {av['version']} ist verfügbar (Signatur geprüft).", data=st)
    if age > 7:
        return chk("ota", "PiOS-Updates (signiert)", "limited", f"Die letzte erfolgreiche Update-Prüfung liegt {age:.0f} Tage zurück.", data=st)
    return chk("ota", "PiOS-Updates (signiert)", "ok", f"Aktuell (Version {st['installed']['version']}), Signaturprüfung mit fest hinterlegtem Schlüssel.", data=st)


def check_os():
    try:
        st = sysops.call("os.status", None, 8)
    except (sysops.Unavailable, sysops.OpError):
        return chk("os", "Betriebssystem-Updates (Debian)", "unknown", "Der System-Dienst antwortet nicht.")
    s = st["status"]
    if not s:
        return chk("os", "Betriebssystem-Updates (Debian)", "unknown", "Es wurde noch nicht nach Debian-Sicherheitsupdates gesucht.", data=st)
    if s.get("signature_ok") is False:
        return chk("os", "Betriebssystem-Updates (Debian)", "critical", "Die Signaturprüfung der Paketquellen ist fehlgeschlagen: " + (s.get("error") or ""), data=st)
    if not s["ok"]:
        return chk("os", "Betriebssystem-Updates (Debian)", "attention", s.get("error") or "Die Update-Prüfung ist fehlgeschlagen.", data=st)
    if s.get("source_problems"):
        return chk("os", "Betriebssystem-Updates (Debian)", "critical", "; ".join(s["source_problems"]), data=st)
    lu = st.get("last_upgrade") or {}
    if lu and not lu.get("ok", True):
        return chk("os", "Betriebssystem-Updates (Debian)", "attention", "Die automatische Installation von Sicherheitsupdates ist fehlgeschlagen: " + (lu.get("error") or ""), data=st)
    if st.get("reboot_required") or s.get("reboot_required"):
        return chk("os", "Betriebssystem-Updates (Debian)", "attention", "Ein Neustart ist erforderlich, damit installierte Sicherheitsupdates wirksam werden.", data=st)
    if s["security"]:
        return chk("os", "Betriebssystem-Updates (Debian)", "attention", f"{len(s['security'])} Sicherheitsupdate(s) ausstehend: " + ", ".join(s["security"][:6]), data=st)
    age = (time.time() - s["checked_at"]) / 86400
    if age > 3:
        return chk("os", "Betriebssystem-Updates (Debian)", "limited", f"Die letzte Prüfung liegt {age:.0f} Tage zurück.", data=st)
    other = len(s["upgradable"])
    return chk("os", "Betriebssystem-Updates (Debian)", "ok", "Keine ausstehenden Sicherheitsupdates; Paketsignaturen geprüft." + (f" {other} weitere Paketupdate(s) verfügbar." if other else "")
               + ("" if st["auto_security"] else " Automatische Installation ist AUS."), data=st)


def check_access():
    now = int(time.time())
    with db.connect() as c:
        sessions = {r["kind"]: r["n"] for r in c.execute("SELECT kind, COUNT(*) AS n FROM sessions WHERE expires>? GROUP BY kind", (now,))}
    failed = audit.count("auth.login_failed", now - 86400)
    locked = audit.count("auth.locked_out", now - 86400)
    detail = f"{sum(sessions.values())} aktive Sitzung(en) ({sessions.get('remote', 0)} Browser, {sessions.get('local', 0)} HDMI); {failed} fehlgeschlagene Anmeldung(en) in 24 h"
    if locked:
        return chk("access", "Anmeldungen", "attention", detail + f", {locked}× gesperrt (Brute-Force-Schutz hat gegriffen).", sessions=sessions, failed_24h=failed)
    if failed >= 10:
        return chk("access", "Anmeldungen", "attention", detail + ". Auffällig viele Fehlversuche.", sessions=sessions, failed_24h=failed)
    return chk("access", "Anmeldungen", "ok", detail + ".", sessions=sessions, failed_24h=failed)


def check_audit():
    v = audit.verify()
    if not v["ok"]:
        return chk("audit", "Sicherheitsprotokoll", "critical", f"Integritätsprüfung fehlgeschlagen ab Eintrag {v['first_bad_id']}: {v['reason']}", data=v)
    return chk("audit", "Sicherheitsprotokoll", "ok", f"{v['entries']} Einträge, Hash-Kette intakt.", data=v)


def check_browser():
    policy = os.environ.get("PIOS_CHROMIUM_POLICY", "/etc/chromium/policies/managed/pios.json")
    script = os.environ.get("PIOS_KIOSK_SCRIPT", "/opt/pios/current/bin/pios-kiosk-browser")
    if not os.path.exists(script):
        return chk("browser", "Browser-Härtung (HDMI-Kiosk)", "info", "Kein HDMI-Kiosk auf diesem System.")
    try:
        text = "\n".join(l for l in open(script).read().splitlines() if not l.lstrip().startswith("#"))   # comments may mention the flags
        bad = [f for f in ("--no-sandbox", "--remote-debugging", "--disable-web-security", "--ignore-certificate-errors", "--disable-site-isolation") if f in text]
        pol_ok = os.path.exists(policy)
    except OSError:
        return chk("browser", "Browser-Härtung (HDMI-Kiosk)", "unknown", "Kiosk-Konfiguration nicht lesbar.")
    if bad:
        return chk("browser", "Browser-Härtung (HDMI-Kiosk)", "critical", "Unsichere Chromium-Parameter: " + ", ".join(bad))
    if not pol_ok:
        return chk("browser", "Browser-Härtung (HDMI-Kiosk)", "limited", "Die Chromium-Richtlinie (nur PiOS erlaubt, keine DevTools) fehlt.")
    return chk("browser", "Browser-Härtung (HDMI-Kiosk)", "ok", "Chromium-Sandbox aktiv, nur PiOS erlaubt, DevTools/Downloads gesperrt, kein Remote-Debugging.")


def check_transport(request: Request):
    https = request.url.scheme == "https"
    return chk("transport", "Verbindung", "info", "Verschlüsselt (HTTPS)." if https else "Unverschlüsselt (HTTP im Heimnetz). Nicht über das Internet freigeben; für Fernzugriff ein VPN verwenden.")



@router.get("")
def overview(request: Request, u=Depends(admin_user)):
    checks = [check_firewall(), check_malware(), check_sandbox(), check_hardening(), check_ota(), check_os(), check_access(), check_audit(), check_browser(), check_transport(request)]
    worst = max(SEVERITY[c["level"]] for c in checks)
    key, label = VERDICT[worst]
    problems = [c for c in checks if SEVERITY[c["level"]] > 0]
    with db.connect() as c:
        threats = c.execute("SELECT COUNT(*) FROM quarantine WHERE state='infected'").fetchone()[0]
    return {"status": key, "label": label, "checks": checks, "threats": threats, "attention": [c["id"] for c in problems],
            "recent_events": audit.recent(8, severity=None), "time": int(time.time())}
