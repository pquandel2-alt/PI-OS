"""Input-device diagnosis: follows a mouse/keyboard through every layer between the USB port (or Bluetooth) and the cage compositor,
and says which layer breaks. Pure evidence gathering (sysfs, procfs, udev database, libinput, logind): nothing is changed."""
import grp
import os
import pwd
import re
import struct
import subprocess
from pathlib import Path

from . import hw

KIOSK_USER = "pios-kiosk"
KIOSK_UNIT = "pios-kiosk.service"


def run(cmd, timeout=8):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except FileNotFoundError:
        return 127, ""
    except subprocess.TimeoutExpired:
        return 124, ""


def stage(sid, title, state, detail, **ev):
    return {"id": sid, "title": title, "state": state, "detail": detail, "evidence": ev}


# ------------------------------------------------------------------ udev database
def udev_props(r: hw.Roots, event: int) -> dict | None:
    p = r.udev / f"c13:{64 + event}"
    try:
        text = p.read_text(errors="replace")
    except OSError:
        return None
    props, tags = {}, set()
    for line in text.splitlines():
        if line.startswith("E:") and "=" in line:
            k, v = line[2:].split("=", 1)
            props[k] = v
        elif line.startswith(("G:", "Q:")):
            tags.add(line[2:].strip())
    return {"props": props, "tags": sorted(tags)}


# ------------------------------------------------------------------ permissions
def parse_acl(raw: bytes) -> list[tuple[str, int, int]]:
    """system.posix_acl_access xattr -> [(kind, id, perm)]; kind in user/group/mask/other/owner/groupobj."""
    if len(raw) < 4 or struct.unpack_from("<I", raw, 0)[0] != 2:
        return []
    tags = {0x01: "owner", 0x02: "user", 0x04: "groupobj", 0x08: "group", 0x10: "mask", 0x20: "other"}
    out = []
    for off in range(4, len(raw) - 7, 8):
        tag, perm, ident = struct.unpack_from("<HHI", raw, off)
        out.append((tags.get(tag, "?"), ident, perm))
    return out


def can_read(path: Path, uid: int, gids: set[int]) -> tuple[bool | None, str]:
    """May a process with this uid/groups open the node for reading? (mode bits + POSIX ACL, as the kernel evaluates them.)"""
    try:
        st = os.stat(path)
    except OSError:
        return None, "Knoten nicht lesbar/vorhanden"
    mode = st.st_mode
    try:
        acl = parse_acl(os.getxattr(path, "system.posix_acl_access"))
    except OSError:
        acl = []
    if acl:
        mask = next((p for k, _i, p in acl if k == "mask"), 7)
        if st.st_uid == uid:
            return bool(mode & 0o400), "Eigentümer"
        for k, i, perm in acl:
            if k == "user" and i == uid:
                return bool(perm & mask & 4), f"ACL-Eintrag für den Benutzer (logind uaccess), Maske {mask:o}"
        if st.st_gid in gids or any(k == "group" and i in gids for k, i, _p in acl):
            ok = any((k == "groupobj" and st.st_gid in gids and p & 4) or (k == "group" and i in gids and p & 4) for k, i, p in acl)
            return ok and bool(mask & 4), "Gruppenrecht (ACL)"
        return bool(mode & 0o004), "andere"
    if st.st_uid == uid:
        return bool(mode & 0o400), "Eigentümer"
    if st.st_gid in gids:
        return bool(mode & 0o040), f"Gruppe {gid_name(st.st_gid)}"
    return bool(mode & 0o004), "andere"


def gid_name(g):
    try:
        return grp.getgrgid(g).gr_name
    except KeyError:
        return str(g)


def kiosk_identity(user=KIOSK_USER):
    try:
        pw = pwd.getpwnam(user)
    except KeyError:
        return None
    gids = {pw.pw_gid} | {g.gr_gid for g in grp.getgrall() if user in g.gr_mem}
    return {"user": user, "uid": pw.pw_uid, "gids": gids, "groups": sorted(gid_name(g) for g in gids)}


# ------------------------------------------------------------------ libinput, logind, compositor
def parse_libinput(text: str) -> list[dict]:
    devs = []
    for block in re.split(r"\n\s*\n", text):
        d = {}
        for line in block.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                d[k.strip()] = v.strip()
        if "Device" in d:
            m = re.search(r"event(\d+)", d.get("Kernel", ""))
            devs.append({"name": d["Device"], "event": int(m.group(1)) if m else None, "seat": d.get("Group", ""), "capabilities": d.get("Capabilities", "").split(), "seat_name": d.get("Seat", "")})
    return devs


def kiosk_sessions(runner, user) -> list[dict]:
    rc, out = runner(["loginctl", "list-sessions", "--no-legend", "--no-pager"])
    if rc != 0:
        return [] if rc != 127 else None
    sess = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2] == user:
            sid = parts[0]
            rc2, info = runner(["loginctl", "show-session", sid, "-p", "Active", "-p", "State", "-p", "Type", "-p", "Seat", "-p", "VTNr", "-p", "Class"])
            d = dict(l.split("=", 1) for l in info.splitlines() if "=" in l)
            sess.append({"id": sid, **{k.lower(): v for k, v in d.items()}})
    return sess


def find_processes(proc: Path, comm: str) -> list[int]:
    out = []
    try:
        for d in proc.iterdir():
            if d.name.isdigit():
                try:
                    if (d / "comm").read_text().strip() == comm:
                        out.append(int(d.name))
                except OSError:
                    pass
    except OSError:
        pass
    return out


def compositor_fds(proc: Path, pid: int) -> dict:
    ev, dri = set(), 0
    try:
        for fd in (proc / str(pid) / "fd").iterdir():
            try:
                t = os.readlink(fd)
            except OSError:
                continue
            m = re.fullmatch(r"/dev/input/event(\d+)", t)
            if m:
                ev.add(int(m.group(1)))
            elif t.startswith("/dev/dri/"):
                dri += 1
    except OSError:
        return {"readable": False, "events": set(), "dri": 0}
    env = {}
    try:
        for kv in (proc / str(pid) / "environ").read_bytes().split(b"\0"):
            k, _, v = kv.partition(b"=")
            if k.startswith(b"WLR_") or k in (b"XDG_SESSION_ID", b"XDG_SEAT"):
                env[k.decode()] = v.decode(errors="replace")
    except OSError:
        pass
    return {"readable": True, "events": ev, "dri": dri, "env": env}


# ------------------------------------------------------------------ the diagnosis
def diagnose(r: hw.Roots = None, runner=run, kiosk=None) -> dict:
    r = r or hw.Roots()
    kiosk = kiosk if kiosk is not None else kiosk_identity()
    usb = hw.usb_devices(r)
    inputs = hw.input_devices(r)
    stages, hints = [], []

    # 1) USB layer ---------------------------------------------------------------------------------
    hid = []
    for u in usb:
        for i in u["interfaces"]:
            role = hw.hid_role(i)
            if role:
                hid.append({"usb": u, "iface": i, "role": role})
    if hid:
        stages.append(stage("usb", "USB-Gerät mit HID-Schnittstelle erkannt", "ok", "; ".join(f"{h['usb']['product'] or 'USB-Gerät'} ({h['usb']['vendor_id']}:{h['usb']['product_id']}, {h['role']})" for h in hid), devices=len(hid)))
    else:
        has_bt = any(d["transport"] == "bluetooth" for d in inputs)
        stages.append(stage("usb", "USB-Gerät mit HID-Schnittstelle erkannt", "warn" if has_bt else "fail",
                            "Es ist kein USB-Gerät mit HID-Schnittstelle (Maus/Tastatur) sichtbar." + (" Es gibt aber ein Bluetooth-Eingabegerät." if has_bt else
                            " Funkempfänger nicht eingesteckt, anderer USB-Port nötig, Gerät/Port defekt oder die Maus nutzt Bluetooth statt eines Empfängers."), usb_devices=len([u for u in usb if not u["is_hub"]])))
    # 2) kernel HID drivers ---------------------------------------------------------------------------
    have_usbhid = (r.sys / "bus/usb/drivers/usbhid").exists() or (r.sys / "module/usbhid").exists()
    have_hidgen = (r.sys / "bus/hid/drivers/hid-generic").exists() or (r.sys / "module/hid_generic").exists()
    if have_usbhid and have_hidgen:
        stages.append(stage("kernel", "Kernel-Treiber für USB-HID (usbhid, hid-generic)", "ok", "Beide Treiber sind im laufenden Kernel vorhanden.", usbhid=True, hid_generic=True))
    else:
        stages.append(stage("kernel", "Kernel-Treiber für USB-HID (usbhid, hid-generic)", "fail",
                            f"Im laufenden Kernel fehlt: {', '.join(n for n, ok in (('usbhid', have_usbhid), ('hid-generic', have_hidgen)) if not ok)}. Ohne diese Treiber entstehen keine Eingabegeräte.", usbhid=have_usbhid, hid_generic=have_hidgen))
    # 3) driver binding of the HID interfaces ------------------------------------------------------------
    unbound = [h for h in hid if not h["iface"]["driver"]]
    if hid:
        if unbound:
            stages.append(stage("binding", "HID-Schnittstelle an einen Treiber gebunden", "fail", "Nicht gebunden: " + ", ".join(h["usb"]["product"] or h["usb"]["vendor_id"] for h in unbound) + ". Das Gerät wird erkannt, aber kein Treiber hat es übernommen.", unbound=len(unbound)))
        else:
            stages.append(stage("binding", "HID-Schnittstelle an einen Treiber gebunden", "ok", ", ".join(sorted({h["iface"]["driver"] for h in hid})), drivers=sorted({h["iface"]["driver"] for h in hid})))
    # 4) input devices created by the kernel -------------------------------------------------------------------
    pointer = [d for d in inputs if d["mouse"] and d["transport"] in ("usb", "bluetooth")]
    keyboards = [d for d in inputs if d["keyboard"] and d["transport"] in ("usb", "bluetooth")]
    matched = []
    for h in hid:
        vp = (h["usb"]["vendor_id"].lower(), h["usb"]["product_id"].lower())
        matched.append((h, [d for d in inputs if d["transport"] == "usb" and (d["vendor"].lower(), d["product"].lower()) == vp]))
    missing = [h for h, devs in matched if not devs and h["iface"]["driver"]]
    if hid and missing:
        stages.append(stage("input", "Kernel hat ein Eingabegerät (/dev/input/event*) erzeugt", "fail", "Treiber gebunden, aber kein Eingabegerät entstanden für: " + ", ".join(h["usb"]["product"] or h["usb"]["vendor_id"] for h in missing) +
                            ". Typisch für Empfänger, die erst nach Pairing/Aktivierung der Maus Eingaben melden, oder für Geräte mit herstellerspezifischem HID-Protokoll.", missing=len(missing)))
    else:
        stages.append(stage("input", "Kernel hat ein Eingabegerät (/dev/input/event*) erzeugt", "ok" if (pointer or keyboards) else ("fail" if hid else "warn"),
                            ("Zeigegeräte: " + ", ".join(f"{d['name']} (event{d['event']}, {d['transport']})" for d in pointer) if pointer else "Kein Zeigegerät (Maus/Touchpad) vorhanden.") +
                            ("; Tastaturen: " + ", ".join(d["name"] for d in keyboards) if keyboards else ""), pointers=[{"name": d["name"], "event": d["event"], "transport": d["transport"]} for d in pointer]))
    targets = pointer or keyboards
    # 5) udev classification ----------------------------------------------------------------------------------------
    bad_udev, udev_info = [], {}
    for d in targets:
        u = udev_props(r, d["event"]) if d["event"] is not None else None
        udev_info[d["event"]] = u
        if not u or u["props"].get("ID_INPUT") != "1" or not (u["props"].get("ID_INPUT_MOUSE") or u["props"].get("ID_INPUT_KEYBOARD") or u["props"].get("ID_INPUT_TOUCHPAD") or u["props"].get("ID_INPUT_POINTINGSTICK")):
            bad_udev.append(d)
    if targets:
        stages.append(stage("udev", "udev hat das Gerät als Eingabegerät klassifiziert", "fail" if bad_udev else "ok",
                            ("Nicht klassifiziert: " + ", ".join(d["name"] for d in bad_udev) + ". libinput und Compositor ignorieren solche Geräte; systemd-udevd/hwdb prüfen.") if bad_udev else "ID_INPUT_MOUSE/ID_INPUT_KEYBOARD gesetzt.", events=[d["event"] for d in targets]))
    # 6) seat / permission for the kiosk user ------------------------------------------------------------------------------
    perm = {}
    if targets and kiosk:
        for d in targets:
            ok, why = can_read(r.dev / f"input/event{d['event']}", kiosk["uid"], kiosk["gids"])
            perm[d["event"]] = (ok, why)
        denied = [d for d in targets if perm[d["event"]][0] is False]
        stages.append(stage("access", f"Benutzer {kiosk['user']} darf die Geräteknoten lesen (Modus/Gruppe/ACL)", "warn" if denied else "ok",
                            ("Direkter Zugriff verweigert für " + ", ".join(f"event{d['event']}" for d in denied) + " – das ist normal, solange der Compositor die Geräte über logind erhält (siehe Sitzung)." if denied else
                             "Lesezugriff vorhanden: " + "; ".join(f"event{e}: {w}" for e, (_o, w) in perm.items())), groups=kiosk["groups"], nodes={f"event{e}": {"readable": o, "reason": w} for e, (o, w) in perm.items()}))
    elif targets and not kiosk:
        stages.append(stage("access", "Kiosk-Benutzer vorhanden", "fail", f"Der Benutzer {KIOSK_USER} existiert nicht – der HDMI-Desktop kann nicht laufen."))
    # 7) libinput ------------------------------------------------------------------------------------------------------------
    rc, out = runner(["libinput", "list-devices"])
    if rc == 127:
        stages.append(stage("libinput", "libinput erkennt das Gerät", "unknown", "libinput-tools ist nicht installiert; die Prüfung konnte nicht stattfinden."))
    elif rc != 0:
        stages.append(stage("libinput", "libinput erkennt das Gerät", "unknown", "libinput list-devices lieferte keinen Status."))
    else:
        li = parse_libinput(out)
        seen = {d["event"] for d in li if d["event"] is not None}
        lost = [d for d in targets if d["event"] not in seen]
        ptr_ok = [d for d in li if "pointer" in d["capabilities"]]
        stages.append(stage("libinput", "libinput erkennt das Gerät", "fail" if (targets and lost) else "ok",
                            ("libinput sieht nicht: " + ", ".join(d["name"] for d in lost)) if (targets and lost) else f"{len(ptr_ok)} Zeigegerät(e), {len([d for d in li if 'keyboard' in d['capabilities']])} Tastatur(en) erkannt.", libinput=[d["name"] for d in li]))
    # 8) logind session ---------------------------------------------------------------------------------------------------------
    sessions = kiosk_sessions(runner, kiosk["user"]) if kiosk else None
    active_unit = runner(["systemctl", "is-active", KIOSK_UNIT])[1].strip().splitlines()[-1:] or [""]
    kiosk_running = active_unit[0] == "active"
    if sessions is None:
        stages.append(stage("session", "systemd-logind-Sitzung des Kiosk", "unknown", "loginctl nicht verfügbar."))
    elif not kiosk_running:
        stages.append(stage("session", "systemd-logind-Sitzung des Kiosk", "warn", "Der HDMI-Desktop (pios-kiosk.service) läuft nicht – er startet nur bei angeschlossenem Monitor. Eingabegeräte können erst dann geprüft werden.", unit=active_unit[0]))
    elif not sessions:
        stages.append(stage("session", "systemd-logind-Sitzung des Kiosk", "fail", "pios-kiosk läuft, aber logind kennt keine Sitzung des Benutzers. Ohne Sitzung gibt logind dem Compositor keine Eingabegeräte (PAM/pam_systemd prüfen).", unit="active"))
    else:
        s = sessions[0]
        good = s.get("active") == "yes" and s.get("seat") == "seat0"
        stages.append(stage("session", "systemd-logind-Sitzung des Kiosk", "ok" if good else "fail",
                            f"Sitzung {s['id']}: aktiv={s.get('active')}, Seat={s.get('seat') or '–'}, VT={s.get('vtnr') or '–'}, Typ={s.get('type') or '–'}." + ("" if good else " Die Sitzung ist nicht aktiv auf seat0: Eingabegeräte werden nicht freigegeben (VT-Wechsel? getty@tty1 läuft parallel?)."), session=s))
    # 9) compositor really opened the devices --------------------------------------------------------------------------------------
    cage = find_processes(r.proc, "cage")
    if kiosk_running and not cage:
        stages.append(stage("compositor", "Compositor (cage) läuft und hat Eingabegeräte geöffnet", "fail", "pios-kiosk ist aktiv, aber kein cage-Prozess läuft."))
    elif cage:
        info = compositor_fds(r.proc, cage[0])
        if not info["readable"]:
            stages.append(stage("compositor", "Compositor (cage) läuft und hat Eingabegeräte geöffnet", "unknown", "Dateideskriptoren von cage nicht lesbar."))
        else:
            want = {d["event"] for d in targets}
            opened = info["events"]
            if not opened:
                stages.append(stage("compositor", "Compositor (cage) läuft und hat Eingabegeräte geöffnet", "fail", f"cage läuft (PID {cage[0]}, {info['dri']} DRM-Handle), hat aber KEIN Eingabegerät geöffnet – der Compositor erhält keine Geräte (Sitzung/Seat/Rechte).", dri=info["dri"]))
            elif want and not (want & opened):
                stages.append(stage("compositor", "Compositor (cage) läuft und hat Eingabegeräte geöffnet", "fail", "cage hat Eingabegeräte geöffnet (" + ", ".join(f"event{e}" for e in sorted(opened)) + "), aber nicht das Zeigegerät/die Tastatur " + ", ".join(f"event{e}" for e in sorted(want)) + " – Gerät nach dem Start angesteckt und nicht übernommen?", opened=sorted(opened), wanted=sorted(want)))
            else:
                stages.append(stage("compositor", "Compositor (cage) läuft und hat Eingabegeräte geöffnet", "ok", f"cage (PID {cage[0]}) hat {len(opened)} Eingabegerät(e) geöffnet: " + ", ".join(f"event{e}" for e in sorted(opened)) + ".", opened=sorted(opened)))
            cur = info.get("env", {}).get("WLR_NO_HARDWARE_CURSORS")
            if cur == "0":
                stages.append(stage("cursor", "Mauszeiger-Darstellung", "warn", "Hardware-Cursor ist erzwungen (WLR_NO_HARDWARE_CURSORS=0). Auf dem Raspberry Pi (vc4/KMS) bleibt der Zeiger dann oft unsichtbar, obwohl die Maus funktioniert. Empfohlen: Software-Cursor (WLR_NO_HARDWARE_CURSORS=1).", env=info["env"]))
            elif cur == "1":
                stages.append(stage("cursor", "Mauszeiger-Darstellung", "ok", "Software-Cursor aktiv (WLR_NO_HARDWARE_CURSORS=1).", env=info["env"]))
            else:
                stages.append(stage("cursor", "Mauszeiger-Darstellung", "warn", "Cursor-Modus nicht gesetzt (Compositor-Standard: Hardware-Cursor, wenn möglich). Falls die Maus reagiert, aber kein Zeiger sichtbar ist: WLR_NO_HARDWARE_CURSORS=1 setzen.", env=info["env"]))
    # kernel log hints for USB problems --------------------------------------------------------------------------------------------
    rc, klog = runner(["journalctl", "-k", "-b", "--no-pager", "-o", "cat", "-n", "600"])
    if rc == 0:
        for pat, msg in ((r"over-current", "USB-Überstrom gemeldet: Stromversorgung/Port prüfen"), (r"device descriptor read/\d+, error -\d+|error -71|Cannot enable\. Maybe the USB cable is bad", "USB-Kommunikationsfehler (Kabel, Port oder Stromversorgung)"),
                         (r"usb \S+: Not enough power|power budget", "USB-Strombudget überschritten (Netzteil, Hub ohne eigene Stromversorgung)"), (r"hid-generic.*: .*(failed|error)", "HID-Treiber meldet Fehler")):
            if re.search(pat, klog):
                hints.append(msg)
    return {"stages": stages, "verdict": verdict(stages, bool(targets), bool(hid), kiosk_running), "hints": hints,
            "devices": {"pointers": [{"name": d["name"], "event": d["event"], "transport": d["transport"], "vendor": d["vendor"], "product": d["product"]} for d in pointer],
                        "keyboards": [{"name": d["name"], "event": d["event"], "transport": d["transport"]} for d in keyboards]}}


def verdict(stages, have_target, have_usb_hid, kiosk_running) -> dict:
    order = ["usb", "kernel", "binding", "input", "udev", "libinput", "session", "compositor", "cursor", "access"]
    by = {s["id"]: s for s in stages}
    for sid in order:
        s = by.get(sid)
        if s and s["state"] == "fail":
            return {"state": "fail", "stage": sid, "cause": s["detail"], "title": s["title"]}
    warns = [by[sid] for sid in order if sid in by and by[sid]["state"] == "warn" and sid in ("cursor", "session", "usb")]
    if have_target and kiosk_running and by.get("compositor", {}).get("state") == "ok":
        cur = by.get("cursor")
        if cur and cur["state"] == "warn":
            return {"state": "warn", "stage": "cursor", "cause": "Das Gerät ist erkannt und vom Compositor geöffnet. Wenn die Maus trotzdem 'nicht funktioniert', ist sehr wahrscheinlich der Cursor unsichtbar: " + cur["detail"], "title": cur["title"]}
        return {"state": "ok", "stage": "compositor", "cause": "Alle Schichten vom USB-/Bluetooth-Gerät bis zum Compositor sind in Ordnung.", "title": "Eingabegeräte funktionieren"}
    if warns:
        s = warns[0]
        return {"state": "warn", "stage": s["id"], "cause": s["detail"], "title": s["title"]}
    return {"state": "unknown", "stage": "", "cause": "Nicht genug Informationen für eine Aussage (keine Eingabegeräte oder Kiosk nicht aktiv).", "title": ""}
