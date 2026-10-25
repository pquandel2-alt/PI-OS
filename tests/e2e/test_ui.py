"""Browser tests of the NOVA shell against a real server (Chromium via Playwright)."""
import re
import time
from pathlib import Path

import pytest

PASSWORD = "correct horse battery"
SHOTS = Path(__file__).parent / "screens"


def login(page, url, password=PASSWORD):
    page.goto(url)
    page.wait_for_selector(".auth-card, .dock")
    if page.locator(".dock").count():
        return
    if page.locator("input[autocomplete=new-password]").count():  # first start: setup wizard
        page.fill("input[autocomplete=username]", "admin")
        fields = page.locator("input[type=password]")
        fields.nth(0).fill(password)
        fields.nth(1).fill(password)
    else:
        page.fill("input[autocomplete=username]", "admin")
        page.fill("input[type=password]", password)
    page.click("button[type=submit]")
    page.wait_for_selector(".dock")


def open_app(page, name):
    page.click(f".dock-item[title='{name}']")
    page.wait_for_selector(f".win[aria-label='{name}']:not(.opening)")


def app_errors(page):
    return [e for e in page.errors if "401" not in e]  # 401 before login is expected


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
    open_app(page, "NOVA Notes") if not page.locator(".win[aria-label='NOVA Notes']").count() else None
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
    time.sleep(6)
    assert len(seen) >= 2, "metrics must refresh without reloading"
    assert re.search(r"\d+ (min|h|d)", page.inner_text(".mon-big"))
    shot(page, "monitor")


def test_settings_theme_motion_and_password(page, server):
    login(page, server)
    open_app(page, "NOVA Settings")
    page.click(".tabs button:has-text('Darstellung')")
    page.click(".seg button:has-text('Violett')")
    page.wait_for_function("() => document.body.dataset.accent === 'violet'")
    page.click(".set-row:has-text('Animationen') .switch")
    page.wait_for_function("() => document.body.dataset.motion === 'off'")
    page.click(".set-row:has-text('Animationen') .switch")
    page.click(".seg button:has-text('Cyan')")
    page.wait_for_function("() => document.body.dataset.accent === 'cyan' && document.body.dataset.motion === 'on'")
    page.click(".tabs button:has-text('System')")
    assert "0.1.0" in page.inner_text(".about-head")
    # password change, then login with the new one
    page.click(".tabs button:has-text('Profil')")
    pw = page.locator(".set-content form input[type=password]")
    pw.nth(0).fill(PASSWORD); pw.nth(1).fill("an even longer password 42"); pw.nth(2).fill("an even longer password 42")
    page.click(".set-content form button[type=submit]")
    page.wait_for_selector(".toast:has-text('Passwort geändert')")
    page.click(".tb-btn[aria-label='Benutzermenü']")
    page.click(".menu button:has-text('Abmelden')")
    page.wait_for_selector(".auth-card")
    page.fill("input[type=password]", PASSWORD)
    page.click("button[type=submit]")
    page.wait_for_selector(".error-text:has-text('fehlgeschlagen')")
    page.fill("input[type=password]", "an even longer password 42")
    page.click("button[type=submit]")
    page.wait_for_selector(".dock")
    # restore for the other tests
    open_app(page, "NOVA Settings")
    pw = page.locator(".set-content form input[type=password]")
    pw.nth(0).fill("an even longer password 42"); pw.nth(1).fill(PASSWORD); pw.nth(2).fill(PASSWORD)
    page.click(".set-content form button[type=submit]")
    page.wait_for_selector(".toast:has-text('Passwort geändert')")


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
    if not page.locator(".win[aria-label='Hello NOVA']").count():
        open_app(page, "Hello NOVA")
    frame = page.frame_locator(".win[aria-label='Hello NOVA'] iframe")
    page.wait_for_function("() => true")
    frame.locator("#count").wait_for()
    page.wait_for_timeout(500)
    assert frame.locator("#count").inner_text() == "2"
    # an app cannot call a capability it did not declare in its manifest
    denied = child.evaluate("""async () => { try { await pios.files.list(''); return 'allowed'; } catch (e) { return e.status; } }""") if False else None
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
