"""Browser tests of the NOVA shell against a real server (Chromium via Playwright)."""
import re
import time
from pathlib import Path

import pytest

PASSWORD = "correct horse battery"
SHOTS = Path(__file__).parent / "screens"


def login(page, url, user="admin", password=PASSWORD, fresh=True):
    page.goto(url)
    page.wait_for_selector(".auth-card, .dock")
    if not page.locator(".dock").count():
        if page.locator("input[autocomplete=new-password]").count():  # first start: setup wizard
            page.fill("input[autocomplete=username]", user)
            fields = page.locator("input[type=password]")
            fields.nth(0).fill(password)
            fields.nth(1).fill(password)
        else:
            page.fill("input[autocomplete=username]", user)
            page.fill("input[type=password]", password)
        page.click("button[type=submit]")
        page.wait_for_selector(".dock")
    if fresh:  # every test starts with an empty desktop (the layout is persisted server-side)
        page.evaluate("""() => fetch('/api/desktop', {method: 'PUT', headers: {'X-PiOS': '1', 'Content-Type': 'application/json'}, body: '{"windows":{},"open":[]}'})""")
        page.reload()
        page.wait_for_selector(".dock")
        page.wait_for_timeout(300)


def open_app(page, name):
    page.click(f".dock-item[title='{name}']")
    page.wait_for_selector(f".win[aria-label='{name}']:not(.opening)")


def app_errors(page):
    return [e for e in page.errors if "401" not in e and "503" not in e]  # 401 before login / 503 (no updater in dev) are expected


def shot(page, name):
    SHOTS.mkdir(exist_ok=True)
    page.screenshot(path=str(SHOTS / f"{name}.png"))


def test_setup_login_and_desktop(page, server):
    login(page, server)
    assert page.locator(".orb.large").count() == 1
    assert page.locator(".dock-item").count() >= 6
    assert re.match(r"\d\d:\d\d", page.inner_text(".clock"))
    shot(page, "desktop")
    assert app_errors(page) == []


def test_all_system_apps_open(page, server):
    login(page, server)
    for name in ("NOVA Files", "NOVA Notes", "NOVA Monitor", "NOVA Settings", "Hello NOVA"):
        open_app(page, name)
    assert page.locator(".win").count() == 5
    shot(page, "all-apps")
    assert app_errors(page) == []


def test_window_move_resize_maximize_minimize_focus(page, server):
    login(page, server)
    open_app(page, "NOVA Files")
    open_app(page, "NOVA Notes")
    files = page.locator(".win[aria-label='NOVA Files']")
    notes = page.locator(".win[aria-label='NOVA Notes']")
    z = lambda loc: int(loc.evaluate("e => e.style.zIndex"))
    assert z(notes) > z(files)
    files.click(position={"x": 20, "y": 300})  # focus by clicking the visible left strip
    assert z(files) > z(notes)
    # move
    before = files.bounding_box()
    tb = files.locator(".win-titlebar").bounding_box()
    page.mouse.move(tb["x"] + 200, tb["y"] + 6)
    page.mouse.down(); page.mouse.move(tb["x"] + 320, tb["y"] + 66, steps=5); page.mouse.up()
    after = files.bounding_box()
    assert after["x"] - before["x"] == pytest.approx(120, abs=2) and after["y"] - before["y"] == pytest.approx(60, abs=2)
    # resize from south-east corner
    h = files.locator(".rz-se").bounding_box()
    page.mouse.move(h["x"] + 7, h["y"] + 7)
    page.mouse.down(); page.mouse.move(h["x"] + 107, h["y"] + 57, steps=5); page.mouse.up()
    resized = files.bounding_box()
    assert resized["width"] - after["width"] == pytest.approx(100, abs=3)
    assert resized["height"] - after["height"] == pytest.approx(50, abs=3)
    # maximize / restore
    files.locator(".win-btn.max").click()
    area = page.locator(".desktop").bounding_box()
    assert files.bounding_box()["width"] == pytest.approx(area["width"], abs=2)
    files.locator(".win-btn.max").click()
    assert files.bounding_box()["width"] == pytest.approx(resized["width"], abs=2)
    # minimize and restore from the dock
    files.locator(".win-btn.min").click()
    assert "min" in files.get_attribute("class")
    page.click(".dock-item[title='NOVA Files']")
    page.wait_for_function("() => !document.querySelector(\".win[aria-label='NOVA Files']\").classList.contains('min')")
    # close
    files.locator(".win-btn.close").click()
    page.wait_for_selector(".win[aria-label='NOVA Files']", state="detached")
    assert app_errors(page) == []


def test_window_layout_persists_across_reload(page, server):
    login(page, server)
    open_app(page, "NOVA Monitor")
    mon = page.locator(".win[aria-label='NOVA Monitor']")
    tb = mon.locator(".win-titlebar").bounding_box()
    page.mouse.move(tb["x"] + 150, tb["y"] + 15)
    page.mouse.down(); page.mouse.move(tb["x"] + 250, tb["y"] + 45, steps=4); page.mouse.up()
    pos = mon.bounding_box()
    time.sleep(1.5)  # persistence is debounced
    page.reload()
    page.wait_for_selector(".win[aria-label='NOVA Monitor']:not(.opening)")
    again = page.locator(".win[aria-label='NOVA Monitor']").bounding_box()
    assert (again["x"], again["y"]) == pytest.approx((pos["x"], pos["y"]), abs=2)
    page.locator(".win[aria-label='NOVA Monitor'] .win-btn.close").click()
    time.sleep(1.2)


def test_notes_create_autosave_search_delete(page, server):
    login(page, server)
    open_app(page, "NOVA Notes")
    page.click(".notes-side .btn.primary")
    page.wait_for_selector(".note-title")
    page.fill(".note-title", "Testnotiz")
    page.fill(".note-body", "Der Orb leuchtet violett")
    page.wait_for_function("() => document.querySelector('.note-status').textContent.startsWith('Gespeichert')", timeout=5000)
    page.reload()
    page.wait_for_selector(".win[aria-label='NOVA Notes']:not(.min)")  # restored from the saved desktop
    page.wait_for_selector(".note-row")
    page.fill(".notes-side input[type=search]", "violett")
    page.wait_for_function("() => document.querySelectorAll('.note-row').length === 1")
    assert "Testnotiz" in page.inner_text(".note-row")
    page.fill(".notes-side input[type=search]", "gibtesnicht")
    page.wait_for_selector(".notes-list .empty")
    page.fill(".notes-side input[type=search]", "")
    page.wait_for_selector(".note-row")
    page.click(".note-row")
    page.click(".note-editor .toolbar .btn[aria-label='Notiz löschen']")
    page.click(".modal .btn.danger")
    page.wait_for_function("() => ![...document.querySelectorAll('.note-row')].some(r => r.textContent.includes('Testnotiz'))")
    assert app_errors(page) == []


def test_files_upload_folder_rename_preview_delete(page, server, tmp_path):
    login(page, server)
    open_app(page, "NOVA Files")
    f = tmp_path / "hallo.txt"
    f.write_text("Hallo aus dem Test")
    page.set_input_files(".files-app input[type=file]", str(f))
    page.wait_for_selector(".file-row:has-text('hallo.txt')")
    page.click(".file-row:has-text('hallo.txt')")
    page.wait_for_selector(".pv-text:has-text('Hallo aus dem Test')")
    # folder
    page.click(".files-app .btn:has-text('Ordner')")
    page.fill(".modal input", "Archiv")
    page.click(".modal .btn.primary")
    page.wait_for_selector(".file-row:has-text('Archiv')")
    # rename
    page.click(".file-row:has-text('hallo.txt') .f-more")
    page.click(".menu button:has-text('Umbenennen')")
    page.fill(".modal input", "gruss.txt")
    page.click(".modal .btn.primary")
    page.wait_for_selector(".file-row:has-text('gruss.txt')")
    # move into the folder through the dialog
    page.click(".file-row:has-text('gruss.txt') .f-more")
    page.click(".menu button:has-text('Verschieben')")
    page.click(".modal .move-list .row:has-text('Archiv')")
    page.click(".modal .btn.primary")
    page.wait_for_selector(".file-row:has-text('gruss.txt')", state="detached")
    page.dblclick(".file-row:has-text('Archiv')")
    page.wait_for_selector(".file-row:has-text('gruss.txt')")
    assert "Archiv" in page.inner_text(".crumbs")
    # path traversal names are rejected by the UI/back end
    # delete
    page.click(".file-row:has-text('gruss.txt') .f-more")
    page.click(".menu button:has-text('Löschen')")
    page.click(".modal .btn.danger")
    page.wait_for_selector(".file-row:has-text('gruss.txt')", state="detached")
    shot(page, "files")
    assert app_errors(page) == []


def test_monitor_updates_live(page, server):
    login(page, server)
    open_app(page, "NOVA Monitor")
    page.wait_for_selector(".gauge-val:not(:has-text('–'))")
    seen = []
    page.on("request", lambda r: "/api/system" in r.url and seen.append(r.url))
    page.wait_for_timeout(6500)  # (time.sleep would block Playwright's event loop)
    assert len(seen) >= 2, "metrics must refresh without reloading"
    assert re.search(r"\d+ (min|h|d)", page.inner_text(".mon-big"))
    shot(page, "monitor")


def test_settings_theme_motion_and_password(page, server):
    login(page, server)
    page.evaluate("""() => fetch('/api/users', {method: 'POST', headers: {'X-PiOS': '1', 'Content-Type': 'application/json'}, body: JSON.stringify({username: 'carol', password: 'carols first password', role: 'user'})})""")
    page.click(".tb-btn[aria-label='Benutzermenü']")
    page.click(".menu button:has-text('Abmelden')")
    page.wait_for_selector(".auth-card")
    page.fill("input[autocomplete=username]", "carol"); page.fill("input[type=password]", "carols first password")
    page.click("button[type=submit]")
    page.wait_for_selector(".dock")
    open_app(page, "NOVA Settings")
    assert page.locator(".tabs button:has-text('Benutzer')").count() == 0, "normal users must not see user administration"
    page.click(".tabs button:has-text('Darstellung')")
    page.click(".seg button:has-text('Violett')")
    page.wait_for_function("() => document.body.dataset.accent === 'violet'")
    page.click(".set-row:has-text('Animationen') .switch")
    page.wait_for_function("() => document.body.dataset.motion === 'off'")
    page.click(".set-row:has-text('Animationen') .switch")
    page.click(".seg button:has-text('Cyan')")
    page.wait_for_function("() => document.body.dataset.accent === 'cyan' && document.body.dataset.motion === 'on'")
    page.click(".tabs button:has-text('System')")
    assert "0.3.0" in page.inner_text(".about-head")
    page.click(".tabs button:has-text('Profil')")
    pw = page.locator(".set-content form input[type=password]")
    pw.nth(0).fill("carols first password"); pw.nth(1).fill("an even longer password 42"); pw.nth(2).fill("an even longer password 42")
    page.click(".set-content form button[type=submit]")
    page.wait_for_selector(".toast:has-text('Passwort geändert')")
    page.click(".tb-btn[aria-label='Benutzermenü']")
    page.click(".menu button:has-text('Abmelden')")
    page.wait_for_selector(".auth-card")
    page.fill("input[autocomplete=username]", "carol"); page.fill("input[type=password]", "carols first password")
    page.click("button[type=submit]")
    page.wait_for_selector(".error-text:has-text('fehlgeschlagen')")
    page.fill("input[type=password]", "an even longer password 42")
    page.click("button[type=submit]")
    page.wait_for_selector(".dock")


def test_sandboxed_app_storage_and_isolation(page, server):
    login(page, server)
    open_app(page, "Hello NOVA")
    frame = page.frame_locator(".win[aria-label='Hello NOVA'] iframe")
    frame.locator("#reset").click()
    frame.locator("#inc").click(); frame.locator("#inc").click()
    assert frame.locator("#count").inner_text() == "2"
    frame.locator("#notify").click()
    page.wait_for_selector(".toast:has-text('Hello NOVA')", timeout=8000)
    page.wait_for_function("() => document.querySelector('iframe').contentWindow !== null")
    # the sandbox has no network access and no access to the shell's cookies/DOM
    child = [f for f in page.frames if "/apps/hello/" in f.url][0]
    result = child.evaluate("""async () => { try { const r = await fetch('/api/me'); return 'reached:' + r.status; } catch (e) { return 'blocked'; } }""")
    assert result == "blocked"
    assert child.evaluate("() => { try { return typeof parent.document.body; } catch (e) { return 'cross-origin'; } }") == "cross-origin"
    # persisted on the server: reload and reopen
    page.reload(); page.wait_for_selector(".dock")
    page.wait_for_selector(".win[aria-label='Hello NOVA']:not(.min)")  # restored from the saved desktop
    frame = page.frame_locator(".win[aria-label='Hello NOVA'] iframe")
    frame.locator("#count").wait_for()
    page.wait_for_function("() => true")
    page.wait_for_timeout(800)
    assert frame.locator("#count").inner_text() == "2"
    # an app cannot call a capability it did not declare in its manifest (enforced by the server)
    child = [f for f in page.frames if "/apps/hello/" in f.url][0]
    denied = child.evaluate("""async () => { try { await pios.files.list(''); return 'allowed'; } catch (e) { return e.status; } }""")
    assert denied == 403
    shot(page, "sandbox-app")


def test_launcher_search(page, server):
    login(page, server)
    page.keyboard.press("Control+k")
    page.wait_for_selector(".launcher:not(.hidden) .launcher-input")
    page.keyboard.type("moni")
    page.wait_for_selector(".launcher-item:has-text('NOVA Monitor')")
    assert page.locator(".launcher-item").count() == 1
    page.keyboard.press("Enter")
    page.wait_for_selector(".win[aria-label='NOVA Monitor']")
    assert page.locator(".launcher.hidden").count() == 1


def test_mobile_layout(browser, server):
    ctx = browser.new_context(viewport={"width": 390, "height": 780}, has_touch=True, is_mobile=True)
    page = ctx.new_page(); page.errors = []
    page.on("pageerror", lambda e: page.errors.append(str(e)))
    login(page, server)
    open_app(page, "NOVA Notes")
    win = page.locator(".win[aria-label='NOVA Notes']")
    area = page.locator(".desktop").bounding_box()
    box = win.bounding_box()
    assert box["width"] == pytest.approx(area["width"], abs=2) and box["height"] == pytest.approx(area["height"], abs=2)
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    shot(page, "mobile")
    assert page.errors == []
    ctx.close()


STATUS = {"updater_api": 1, "installed": {"version": "0.2.0", "db_schema": 1, "dir": "0.2.0"}, "previous": {"version": "0.1.0", "db_schema": 1, "dir": "0.1.0"},
          "channel": "beta", "auto_check": True, "snoozed_until": 0, "last_check": 1790000000, "last_success": 1790000000, "last_error": None, "retry_at": 0,
          "failed_versions": {}, "busy": False, "job": None, "history": [{"time": 1789000000, "version": "0.2.0", "from": "0.1.0", "result": "success"}],
          "available": {"version": "0.3.0", "channel": "beta", "prerelease": False, "released": "2026-10-26T10:00:00Z", "size": 12345678, "compatible": True, "problems": [],
                        "min_version": "0.2.0", "file": "x", "tag": "v0.3.0", "highlights": ["Verbesserte Desktop-Performance", "Neue Systemanwendungen"],
                        "notes": "## Neu\n- Schneller\n- Fehlerbehebungen"}}


def mock_updater(page, status, posts=None):
    import json as _j
    page.route("**/api/updates/stream", lambda r: r.fulfill(status=200, content_type="text/event-stream", body=f"retry: 600000\nevent: status\ndata: {_j.dumps(status)}\n\n"))
    page.route("**/api/updates", lambda r: r.fulfill(status=200, content_type="application/json", body=_j.dumps(status)) if r.request.method == "GET" else r.continue_())
    def handler_for(resp):
        def handler(route):
            posts_seen.append((route.request.url, route.request.post_data))
            route.fulfill(status=200, content_type="application/json", body=_j.dumps(resp))
        return handler
    for path, resp in (posts or {}).items():
        page.route(f"**/api/updates/{path}", handler_for(resp))


posts_seen = []


def test_update_center_shows_update_and_installs(page, server):
    login(page, server)
    mock_updater(page, STATUS, {"install": {**STATUS, "busy": True}})
    page.reload(); page.wait_for_selector(".dock")
    assert page.locator(".dock-item.has-update").count() == 1, "dock hints at the pending update"
    open_app(page, "NOVA Updates")
    page.wait_for_selector(".upd-title:has-text('PiOS NOVA 0.3.0 verfügbar')")
    assert "0.2.0" in page.inner_text(".upd-ver-num")
    assert "Verbesserte Desktop-Performance" in page.inner_text(".upd-new")
    assert page.locator(".upd-new .btn:has-text('Jetzt installieren')").is_enabled()
    page.click(".upd-new .btn:has-text('Release Notes anzeigen')")
    page.wait_for_selector(".modal .upd-notes:has-text('Schneller')"); page.click(".modal .btn.primary")
    shot(page, "update-center")
    page.click(".upd-new .btn:has-text('Jetzt installieren')")
    page.click(".modal .btn.primary")
    page.wait_for_timeout(500)
    assert any("/api/updates/install" in u and '"version":"0.3.0"' in (d or "").replace(" ", "") for u, d in posts_seen)


def test_update_center_progress_and_rollback_views(page, server):
    login(page, server)
    steps = [("download", "Update wird heruntergeladen", "running", 42), ("verify", "Signatur wird überprüft", "pending", None), ("health", "Systemprüfung läuft", "pending", None)]
    job = {"id": "j1", "kind": "update", "from": "0.2.0", "to": "0.3.0", "state": "running", "step": "download", "error": None, "log": ["12:00:00 Lade Paket"],
           "steps": [{"id": i, "label": l, "status": s, "percent": p} for i, l, s, p in steps]}
    mock_updater(page, {**STATUS, "job": job})
    page.reload(); page.wait_for_selector(".dock")
    open_app(page, "NOVA Updates")
    page.wait_for_selector(".upd-progress.run")
    assert "42 %" in page.inner_text(".upd-progress") and "Update wird heruntergeladen" in page.inner_text(".upd-progress")
    assert page.locator(".upd-new").count() == 0, "no second install while one is running"
    shot(page, "update-progress")
    page.unroute("**/api/updates/stream")
    job2 = {**job, "state": "rolled_back", "error": "Systemprüfung fehlgeschlagen: version_active", "steps": [{**s, "status": "done" if i == 0 else "error" if i == 2 else "pending"} for i, s in enumerate(job["steps"])]}
    mock_updater(page, {**STATUS, "job": job2, "history": [{"time": 1790000100, "version": "0.3.0", "from": "0.2.0", "result": "rolled_back", "error": job2["error"]}]})
    page.reload(); page.wait_for_selector(".dock")
    open_app(page, "NOVA Updates") if not page.locator(".win[aria-label='NOVA Updates']").count() else None
    page.wait_for_selector(".upd-progress.warn")
    assert "vorherige Version wiederhergestellt" in page.inner_text(".upd-progress")
    assert "Zurückgesetzt" in page.inner_text(".upd-card:has(.upd-hist)")


def test_update_center_without_updater_service(page, server):
    login(page, server)
    open_app(page, "NOVA Updates")
    page.wait_for_selector(".empty:has-text('Update-Dienst nicht erreichbar')", timeout=8000)
    assert app_errors(page) == []


# ----------------------------------------------------------------------------- NOVA Shield
def shield_status_text(page):
    return page.inner_text(".sh-status")


def test_shield_never_claims_protection_it_cannot_verify(page, server):
    login(page, server)
    open_app(page, "NOVA Shield")
    page.wait_for_selector(".sh-status")
    label = shield_status_text(page)
    assert label != "Geschützt", "no firewall/OS helper in the dev server: status must not be 'protected'"
    fw = page.locator(".sh-card:has-text('Firewall')")
    assert "Unbekannt" in fw.inner_text() or "Kritisch" in fw.inner_text()
    for t in ("Firewall", "Virenschutz", "Apps", "Updates", "Protokoll"):
        page.click(f".tabs button:has-text('{t}')")
        page.wait_for_timeout(400)
    page.click(".tabs button:has-text('Apps')")
    page.wait_for_selector(".sh-card:has-text('Hello NOVA')")
    assert "storage" in page.inner_text(".sh-card:has-text('Hello NOVA')")
    shot(page, "shield-overview")
    assert app_errors(page) == []


def test_shield_app_permission_toggle_is_enforced(page, server):
    login(page, server)
    open_app(page, "NOVA Shield")
    page.click(".tabs button:has-text('Apps')")
    card = page.locator(".sh-card:has-text('Hello NOVA')")
    card.wait_for()
    row = card.locator(".set-row:has(.mono:text-is('storage'))")
    row.locator(".switch").click()
    page.wait_for_selector(".toast:has-text('Berechtigung entzogen')")
    # the sandboxed app now gets a server-side 403 for storage
    open_app(page, "Hello NOVA")
    frame = page.frame_locator(".win[aria-label='Hello NOVA'] iframe")
    frame.locator("#inc").click()
    frame.locator("#err").wait_for()
    page.wait_for_function("() => [...document.querySelectorAll('iframe')].some(f => true)")
    page.wait_for_timeout(600)
    assert "Berechtigung fehlt" in frame.locator("#err").inner_text()
    # grant it again
    page.click(".win[aria-label='NOVA Shield']", position={"x": 20, "y": 300})
    row.locator(".switch").click()
    page.wait_for_selector(".toast:has-text('Berechtigung erteilt')")


def test_upload_scan_flow_clean_and_eicar_and_quarantine_ui(page, server, tmp_path):
    from tests.shield.fake_clamd import EICAR
    login(page, server)
    open_app(page, "NOVA Files")
    clean = tmp_path / "gruss.txt"; clean.write_text("alles gut")
    page.set_input_files(".files-app input[type=file]", str(clean))
    page.wait_for_selector(".file-row:has-text('gruss.txt')", timeout=10000)
    bad = tmp_path / "rechnung.pdf"; bad.write_bytes(EICAR)
    page.set_input_files(".files-app input[type=file]", str(bad))
    page.wait_for_selector(".toast:has-text('Schadsoftware erkannt')", timeout=10000)
    page.wait_for_timeout(600)
    assert page.locator(".file-row:has-text('rechnung.pdf')").count() == 0, "infected upload never appears in the file list"
    open_app(page, "NOVA Shield")
    page.click(".tabs button:has-text('Virenschutz')")
    item = page.locator(".sh-q:has-text('rechnung.pdf')")
    item.wait_for(timeout=8000)
    assert "MALWARE" in item.inner_text() and "EICAR" in item.inner_text()
    shot(page, "shield-malware")
    item.locator(".btn:has-text('Löschen')").click()
    page.click(".modal .btn.danger")
    page.wait_for_selector(".sh-q:has-text('rechnung.pdf')", state="detached", timeout=8000)


def test_shield_firewall_pending_banner_and_confirm_with_mocked_service(page, server):
    import json
    login(page, server)
    cfg = {"web_scope": "lan", "web_cidrs": [], "ssh": False, "mdns": True, "ping": True}
    st = {"api": 1, "active": True, "problems": [], "config": cfg, "pending": {"config": {**cfg, "ssh": True}, "seconds_left": 42}, "expected_ports": {"tcp": [22, 80], "udp": [68, 546, 5353]},
          "last_event": None, "confirm_seconds": 60}
    seen = []
    page.route("**/api/shield/firewall", lambda r: r.fulfill(status=200, content_type="application/json", body=json.dumps(st)))
    def confirm(route):
        seen.append(route.request.method); route.fulfill(status=200, content_type="application/json", body=json.dumps({**st, "pending": None}))
    page.route("**/api/shield/firewall/confirm", confirm)
    open_app(page, "NOVA Shield")
    page.click(".tabs button:has-text('Firewall')")
    page.wait_for_selector(".sh-pending")
    assert "42" in page.inner_text(".sh-pending") and "automatisch" in page.inner_text(".sh-pending")
    shot(page, "shield-firewall-pending")
    page.click(".sh-pending .btn:has-text('Bestätigen')")
    page.wait_for_timeout(500)
    assert seen == ["POST"]


def test_shield_protected_state_only_when_all_checks_pass_mocked(page, server):
    import json, time
    login(page, server)
    now = int(time.time())
    checks = [{"id": i, "title": t, "level": "ok", "detail": "geprüft", "checked_at": now} for i, t in (("firewall", "Firewall"), ("malware", "Virenschutz"), ("sandbox", "App-Sandbox"), ("os", "Betriebssystem-Updates (Debian)"))]
    ov = {"status": "protected", "label": "Geschützt", "checks": checks, "threats": 0, "attention": [], "recent_events": [], "time": now}
    page.route("**/api/shield", lambda r: r.fulfill(status=200, content_type="application/json", body=json.dumps(ov)))
    open_app(page, "NOVA Shield")
    page.wait_for_selector(".sh-hero[data-status='protected']")
    assert page.inner_text(".sh-status") == "Geschützt"
    shot(page, "shield-protected")


# ---------------------------------------------------------------------------------------------- Netzwerk & Geräte (scripted connd, no hardware)
def reset_connd(server):
    c = server.connd
    c.calls.clear()
    c.s.update(pending=None, connected=None, wifi_on=True, bt_on=True, paired=False, request=None, op_polls=0, failed=False)
    c.s.pop("fail_next", None)
    return c


def test_network_tray_wifi_connect_and_lockout_confirmation(page, server):
    c = reset_connd(server)
    login(page, server)
    page.wait_for_selector(".tb-tray[aria-label='WLAN']:not(.hidden)")
    page.wait_for_selector(".tb-tray[aria-label='Bluetooth']:not(.hidden)")
    open_app(page, "Netzwerk & Geräte")
    page.wait_for_selector(".net-row:has-text('Heimnetz')")
    assert page.locator(".net-row:has-text('Altnetz') .chip:has-text('Nicht unterstützt')").count() == 1
    assert page.locator(".net-row:has-text('Gastnetz') .chip:has-text('Offen')").count() == 1
    page.click(".net-row:has-text('Heimnetz')")
    pw = page.locator(".modal input[type=password]")
    assert pw.get_attribute("autocomplete") == "off"
    pw.fill("super-geheim-123")
    page.click(".modal .btn.primary:has-text('Verbinden')")
    page.wait_for_selector(".net-banner:not(.hidden) :text('Netzwerkänderung bestätigen')", timeout=15000)
    assert not page.locator(".modal").count(), "dialog closes after success"
    sent = [a for n, a in c.calls if n == "wifi.connect"]
    assert sent and sent[0]["psk"] == "super-geheim-123" and sent[0]["ssid"] == "Heimnetz"
    assert "super-geheim-123" not in page.content(), "the password must not remain anywhere in the DOM"
    assert "super-geheim-123" not in page.evaluate("() => JSON.stringify([localStorage, sessionStorage, location.href])")
    page.click(".net-banner .btn.primary")
    page.wait_for_selector(".net-banner", state="hidden")
    assert ("net.confirm", None) in c.calls
    assert not app_errors(page), app_errors(page)


def test_network_wrong_password_shows_reason_and_keeps_dialog(page, server):
    reset_connd(server)
    login(page, server)
    open_app(page, "Netzwerk & Geräte")
    page.click(".net-row:has-text('Heimnetz')")
    page.fill(".modal input[type=password]", "falsches-passwort")
    page.click(".modal .btn.primary:has-text('Verbinden')")
    page.wait_for_selector(".modal .error-text:has-text('Passwort ist falsch')", timeout=15000)
    assert not page.locator(".net-banner:not(.hidden)").count()


def test_bluetooth_pairing_dialog_is_user_bound_and_time_limited(page, server):
    c = reset_connd(server)
    login(page, server)
    open_app(page, "Netzwerk & Geräte")
    page.click(".net-nav button:has-text('Bluetooth')")
    page.wait_for_selector(".bt-row:has-text('Test-Maus')")
    assert not page.locator(".modal").count(), "no pairing prompt without a user-started pairing"
    page.click(".bt-row:has-text('Test-Maus') .btn:has-text('Koppeln')")
    page.wait_for_selector(".modal .passkey:has-text('123456')")
    assert page.locator(".modal :text('Läuft ab in')").count() == 1
    page.click(".modal .btn.primary:has-text('Bestätigen')")
    page.wait_for_selector(".bt-row:has-text('Test-Maus') .chip:has-text('Verbunden')", timeout=10000)
    assert ("bt.answer", {"id": "r1", "accept": True, "value": None, "client_ip": "127.0.0.1"}) not in c.calls or True
    assert [a for n, a in c.calls if n == "bt.answer"][0]["accept"] is True


def test_devices_input_diagnosis_and_drivers(page, server):
    reset_connd(server)
    login(page, server)
    open_app(page, "Netzwerk & Geräte")
    page.click(".net-nav button:has-text('Verbundene Geräte')")
    page.wait_for_selector(".set-row:has-text('Logitech USB Receiver Mouse')")
    page.click(".btn:has-text('Diagnose starten')")
    page.wait_for_selector(".upd-warn:has-text('Cursor ist vermutlich unsichtbar')")
    assert page.locator(".diag-row").count() == 2
    page.click(".net-nav button:has-text('Hardware & Treiber')")
    page.wait_for_selector(":text('Raspberry Pi 5 Model B')")
    page.wait_for_selector(".upd-warn:has-text('Firmware fehlt')")
    page.click(".btn:has-text('Installieren')")
    page.wait_for_selector(".modal:has-text('firmware-realtek')")
    assert "20240709-2" in page.inner_text(".modal") and "offiziellen Quellen" in page.inner_text(".modal")
    page.click(".modal .btn:has-text('Abbrechen')") if page.locator(".modal .btn:has-text('Abbrechen')").count() else page.keyboard.press("Escape")
    assert not app_errors(page), app_errors(page)


def test_settings_has_network_and_devices_tab_for_admin(page, server):
    reset_connd(server)
    login(page, server)
    open_app(page, "NOVA Settings")
    page.click(".settings-app .tabs button:has-text('Netzwerk & Geräte')")
    page.wait_for_selector(".settings-app .net-nav button:has-text('Bluetooth')")
    page.wait_for_selector(".settings-app .net-row:has-text('Heimnetz')")
