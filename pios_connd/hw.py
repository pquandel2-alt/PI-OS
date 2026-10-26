"""Hardware inventory from sysfs / procfs / udev data. Read-only, no external commands. All roots are injectable for tests."""
import os
import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Roots:
    sys: Path = Path("/sys")
    proc: Path = Path("/proc")
    dev: Path = Path("/dev")
    udev: Path = Path("/run/udev/data")


def _read(p: Path, default="") -> str:
    try:
        return p.read_text(errors="replace").strip()
    except (OSError, ValueError):
        return default


def _readlink_name(p: Path) -> str:
    try:
        return os.path.basename(os.readlink(p))
    except OSError:
        return ""


def _int(s, base=10, default=None):
    try:
        return int(s, base)
    except (ValueError, TypeError):
        return default


# ------------------------------------------------------------------------ platform
def platform(r: Roots) -> dict:
    model = _read(r.proc / "device-tree/model").rstrip("\x00")
    cpuinfo = _read(r.proc / "cpuinfo")
    def field_of(name):
        m = re.search(rf"^{name}\s*:\s*(.+)$", cpuinfo, re.M)
        return m.group(1).strip() if m else ""
    mem_kb = _int((re.search(r"MemTotal:\s*(\d+)", _read(r.proc / "meminfo")) or [None, None])[1])
    online = _read(r.sys / "devices/system/cpu/online")
    cores = 0
    for part in online.split(","):
        if "-" in part:
            a, b = part.split("-"); cores += int(b) - int(a) + 1
        elif part.strip().isdigit():
            cores += 1
    boot = r.proc / "device-tree/chosen/bootloader"
    def be32(name):
        try:
            return int.from_bytes((boot / name).read_bytes()[:4], "big")
        except OSError:
            return None
    rel = {}
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            k, _, v = line.partition("=")
            rel[k] = v.strip('"')
    except OSError:
        pass
    return {"model": model or "unbekannt", "revision": field_of("Revision"), "cpu": field_of("Model name") or field_of("model name") or "ARM",
            "cores": cores or None, "memory_mb": round(mem_kb / 1024) if mem_kb else None, "kernel": os.uname().release, "arch": os.uname().machine,
            "os": rel.get("PRETTY_NAME", ""), "bootloader_build": be32("build-timestamp"), "bootloader_update": be32("update-timestamp")}


# ------------------------------------------------------------------------ USB
def usb_devices(r: Roots) -> list[dict]:
    base = r.sys / "bus/usb/devices"
    out = []
    try:
        entries = sorted(base.iterdir())
    except OSError:
        return out
    for d in entries:
        if ":" in d.name or not (d / "idVendor").exists():
            continue
        dev = {"id": d.name, "vendor_id": _read(d / "idVendor"), "product_id": _read(d / "idProduct"), "manufacturer": _read(d / "manufacturer"),
               "product": _read(d / "product"), "speed_mbps": _int(_read(d / "speed").split(".")[0]), "class": _read(d / "bDeviceClass"),
               "driver": _readlink_name(d / "driver"), "is_hub": _read(d / "bDeviceClass") == "09", "interfaces": [], "bus": _read(d / "busnum"), "dev": _read(d / "devnum"),
               "max_power_ma": _int(_read(d / "bMaxPower").replace("mA", "")), "authorized": _read(d / "authorized") != "0"}
        for i in sorted(base.glob(f"{d.name}:*")):
            dev["interfaces"].append({"name": i.name, "class": _read(i / "bInterfaceClass"), "subclass": _read(i / "bInterfaceSubClass"), "protocol": _read(i / "bInterfaceProtocol"),
                                      "driver": _readlink_name(i / "driver"), "modalias": _read(i / "modalias")})
        out.append(dev)
    return out


def hid_role(iface: dict) -> str:
    """USB HID boot protocol: class 03, subclass 01 (boot), protocol 01 = keyboard, 02 = mouse."""
    if iface["class"] != "03":
        return ""
    return {"01": "keyboard", "02": "mouse"}.get(iface["protocol"], "hid") if iface["subclass"] == "01" else "hid"


# ------------------------------------------------------------------------ input devices (/proc/bus/input/devices)
def input_devices(r: Roots) -> list[dict]:
    text = _read(r.proc / "bus/input/devices")
    out = []
    for block in re.split(r"\n\s*\n", text):
        if not block.strip():
            continue
        d = {"name": "", "bus": "", "vendor": "", "product": "", "phys": "", "sysfs": "", "uniq": "", "handlers": [], "event": None, "mouse": False, "keyboard": False, "ev": 0, "rel": 0}
        for line in block.splitlines():
            if line.startswith("I:"):
                m = re.search(r"Bus=(\w+) Vendor=(\w+) Product=(\w+)", line)
                if m:
                    d["bus"], d["vendor"], d["product"] = m.groups()
            elif line.startswith("N: Name="):
                d["name"] = line.split("=", 1)[1].strip('"')
            elif line.startswith("P: Phys="):
                d["phys"] = line.split("=", 1)[1]
            elif line.startswith("S: Sysfs="):
                d["sysfs"] = line.split("=", 1)[1]
            elif line.startswith("U: Uniq="):
                d["uniq"] = line.split("=", 1)[1]
            elif line.startswith("H: Handlers="):
                d["handlers"] = line.split("=", 1)[1].split()
            elif line.startswith("B: EV="):
                d["ev"] = _int(line.split("=", 1)[1], 16, 0)
            elif line.startswith("B: REL="):
                d["rel"] = _int(line.split("=", 1)[1], 16, 0)
        ev = next((h for h in d["handlers"] if h.startswith("event")), None)
        d["event"] = int(ev[5:]) if ev and ev[5:].isdigit() else None
        d["mouse"] = any(h.startswith("mouse") for h in d["handlers"]) or (bool(d["ev"] & 0x4) and (d["rel"] & 0x3) == 0x3)
        d["keyboard"] = "kbd" in d["handlers"]
        d["transport"] = {"0003": "usb", "0005": "bluetooth", "0019": "intern", "0006": "virtuell", "0011": "ps2", "0018": "i2c"}.get(d["bus"], d["bus"])
        out.append(d)
    return out


# ------------------------------------------------------------------------ network adapters, rfkill, bluetooth
def net_adapters(r: Roots) -> list[dict]:
    out = []
    try:
        names = sorted(p.name for p in (r.sys / "class/net").iterdir())
    except OSError:
        return out
    for n in names:
        if n == "lo":
            continue
        p = r.sys / "class/net" / n
        wireless = (p / "wireless").exists() or (p / "phy80211").exists()
        speed = _int(_read(p / "speed"))
        out.append({"iface": n, "kind": "wifi" if wireless else "ethernet" if _read(p / "type") == "1" and not n.startswith(("docker", "veth", "br-", "virbr")) else "virtual",
                    "mac": _read(p / "address").upper(), "state": _read(p / "operstate"), "carrier": _read(p / "carrier") == "1", "speed_mbps": speed if speed and speed > 0 else None,
                    "driver": _readlink_name(p / "device/driver"), "bus": _readlink_name(p / "device/subsystem"), "mtu": _int(_read(p / "mtu")),
                    "modalias": _read(p / "device/modalias")})
    return out


def rfkill(r: Roots) -> list[dict]:
    out = []
    try:
        entries = sorted((r.sys / "class/rfkill").iterdir())
    except OSError:
        return out
    for p in entries:
        out.append({"id": p.name, "type": _read(p / "type"), "name": _read(p / "name"), "soft_blocked": _read(p / "soft") == "1", "hard_blocked": _read(p / "hard") == "1"})
    return out


def bluetooth_controllers(r: Roots) -> list[dict]:
    out = []
    try:
        entries = sorted((r.sys / "class/bluetooth").iterdir())
    except OSError:
        return out
    for p in entries:
        if not re.fullmatch(r"hci\d+", p.name):
            continue
        dev = p / "device"
        out.append({"name": p.name, "bus": _readlink_name(dev / "subsystem") or ("uart" if "serial" in str(os.path.realpath(p)) else ""), "driver": _readlink_name(dev / "driver"),
                    "path": os.path.realpath(p).replace(str(r.sys), "")[:120]})
    return out


# ------------------------------------------------------------------------ audio, display, storage
def audio(r: Roots) -> list[dict]:
    out = []
    for m in re.finditer(r"^\s*(\d+)\s+\[(\S+)\s*\]:\s*(\S+)\s*-\s*(.+)$", _read(r.proc / "asound/cards"), re.M):
        out.append({"card": int(m.group(1)), "id": m.group(2), "driver": m.group(3), "name": m.group(4).strip()})
    return out


def parse_edid(raw: bytes) -> dict:
    if len(raw) < 128 or raw[:8] != b"\x00\xff\xff\xff\xff\xff\xff\x00":
        return {}
    m = (raw[8] << 8) | raw[9]
    vendor = "".join(chr(((m >> s) & 0x1F) + 64) for s in (10, 5, 0))
    name = ""
    for off in (54, 72, 90, 108):
        blk = raw[off:off + 18]
        if blk[:3] == b"\x00\x00\x00" and blk[3] == 0xFC:
            name = blk[5:18].split(b"\n")[0].decode("ascii", "replace").strip()
    w_cm, h_cm = raw[21], raw[22]
    return {"vendor": vendor, "name": name, "product_code": raw[10] | (raw[11] << 8), "size_cm": (w_cm, h_cm) if w_cm and h_cm else None}


def displays(r: Roots) -> list[dict]:
    out = []
    try:
        entries = sorted((r.sys / "class/drm").iterdir())
    except OSError:
        return out
    for p in entries:
        if not re.match(r"card\d+-", p.name) or not (p / "status").exists():
            continue
        status = _read(p / "status")
        try:
            edid = parse_edid((p / "edid").read_bytes()) if status == "connected" else {}
        except OSError:
            edid = {}
        modes = _read(p / "modes").splitlines()
        out.append({"connector": p.name.split("-", 1)[1], "status": status, "enabled": _read(p / "enabled"), "monitor": edid.get("name") or "", "vendor": edid.get("vendor", ""),
                    "mode": modes[0] if modes else "", "modes": len(modes)})
    return out


def storage(r: Roots) -> list[dict]:
    out = []
    try:
        entries = sorted((r.sys / "block").iterdir())
    except OSError:
        return out
    for p in entries:
        if re.match(r"(loop|ram|zram|dm-|md|nbd)", p.name):
            continue
        real = os.path.realpath(p)
        transport = "nvme" if "nvme" in p.name else "sd/mmc" if p.name.startswith("mmcblk") else "usb" if "/usb" in real else "sata" if p.name.startswith("sd") else ""
        sectors = _int(_read(p / "size"), default=0) or 0
        out.append({"name": p.name, "model": _read(p / "device/model") or _read(p / "device/name"), "vendor": _read(p / "device/vendor"), "size_gb": round(sectors * 512 / 1e9, 1),
                    "removable": _read(p / "removable") == "1", "rotational": _read(p / "queue/rotational") == "1", "transport": transport, "readonly": _read(p / "ro") == "1"})
    return out


# ------------------------------------------------------------------------ driver binding / problems
def modalias_has_module(modalias: str, runner) -> bool | None:
    """Does the running kernel ship a module for this device? (modprobe --resolve-alias; None if the check is unavailable)."""
    if not re.fullmatch(r"[A-Za-z0-9:_*.-]{3,300}", modalias or ""):
        return None
    rc, out = runner(["modprobe", "--resolve-alias", modalias])
    if rc == 127:
        return None
    return rc == 0 and bool(out.strip())


def inventory(r: Roots = None, runner=None) -> dict:
    r = r or Roots()
    usb = usb_devices(r)
    nets = net_adapters(r)
    problems = []
    for u in usb:
        if u["is_hub"]:
            continue
        for i in u["interfaces"]:
            if not i["driver"] and i["class"] not in ("00", ""):
                has = modalias_has_module(i["modalias"], runner) if runner else None
                problems.append({"device": u["product"] or f"{u['vendor_id']}:{u['product_id']}", "where": "USB", "id": f"{u['vendor_id']}:{u['product_id']}", "interface": i["name"],
                                 "problem": "Kein Treiber gebunden", "kernel_module_available": has,
                                 "detail": "Für diese USB-Schnittstelle gibt es im laufenden Kernel kein passendes Modul." if has is False else
                                           "Ein Kernelmodul existiert, ist aber nicht geladen." if has else "Treiberstatus unbekannt."})
    for n in nets:
        if n["kind"] in ("wifi", "ethernet") and not n["driver"]:
            problems.append({"device": n["iface"], "where": "Netzwerk", "id": n["modalias"], "problem": "Kein Treiber gebunden", "kernel_module_available": None, "detail": ""})
    return {"platform": platform(r), "usb": usb, "input": input_devices(r), "network": nets, "rfkill": rfkill(r), "bluetooth": bluetooth_controllers(r), "audio": audio(r),
            "displays": displays(r), "storage": storage(r), "problems": problems}
