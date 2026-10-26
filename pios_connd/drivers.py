"""Driver / firmware analysis from trustworthy system evidence: the kernel log (what the kernel itself says it could not load), the
device's modalias (does the running kernel ship a module for it) and the package manager's view of official sources.
Nothing is downloaded or installed here; installation of an allow-listed package is done by pios-sysops after the user confirmed it."""
import re

# Firmware file (as named in the kernel log) -> Debian/Raspberry Pi OS packages that ship it. Curated, not guessed from the internet.
FIRMWARE_PACKAGES = [
    (r"^regulatory\.db(\.p7s)?$", ["wireless-regdb"], "Regulatory-Datenbank für WLAN-Länderregeln"),
    (r"^brcm/brcmfmac", ["firmware-brcm80211"], "Broadcom/Cypress WLAN (Raspberry Pi onboard)"),
    (r"^brcm/BCM.*\.hcd$", ["bluez-firmware", "firmware-brcm80211"], "Broadcom Bluetooth"),
    (r"^(rtlwifi|rtw88|rtw89)/", ["firmware-realtek"], "Realtek WLAN"),
    (r"^rtl_nic/", ["firmware-realtek"], "Realtek Ethernet"),
    (r"^rtl_bt/", ["firmware-realtek"], "Realtek Bluetooth"),
    (r"^(mediatek|mt7\d+)", ["firmware-mediatek"], "MediaTek WLAN/Bluetooth"),
    (r"^(ath9k_htc|ath10k|ath11k|ath12k|qca|htc_)", ["firmware-atheros"], "Atheros/Qualcomm WLAN/Bluetooth"),
    (r"^iwlwifi-", ["firmware-iwlwifi"], "Intel WLAN"),
    (r"^intel/ibt-", ["firmware-intel-misc"], "Intel Bluetooth"),
    (r"^(libertas|mrvl)/", ["firmware-libertas", "firmware-misc-nonfree"], "Marvell WLAN"),
    (r"^amdgpu/", ["firmware-amd-graphics"], "AMD Grafik"),
]
# Everything pios-sysops may ever install on behalf of the driver manager (the single source of truth is pios_sysops.packages).
OFFICIAL_ORIGINS = ("deb.debian.org", "security.debian.org", "archive.raspberrypi.com", "archive.raspberrypi.org", "ftp.debian.org")
FW_LINE = re.compile(r"(?:Direct firmware load for|firmware: failed to load|Falling back to sysfs fallback for:?)\s+(\S+)", re.I)


def missing_firmware(klog: str) -> list[dict]:
    """Files the kernel failed to load, with the package that normally contains each (if known)."""
    seen: dict[str, dict] = {}
    for m in FW_LINE.finditer(klog or ""):
        f = m.group(1).strip(",:")
        if f in seen:
            continue
        ctx = next((l for l in klog.splitlines() if f in l), "")
        optional = bool(re.search(r"optional|-ENOENT.*regdb|error -2$", ctx)) and not re.search(r"brcm|BCM|rtl|iwl|ath|mt7|regulatory", f)
        pkgs, what = [], ""
        for pat, p, desc in FIRMWARE_PACKAGES:
            if re.search(pat, f):
                pkgs, what = p, desc
                break
        seen[f] = {"file": f, "packages": pkgs, "device": what, "line": ctx[-200:], "known": bool(pkgs), "optional": optional}
    return list(seen.values())


def parse_policy(text: str) -> dict:
    """`apt-cache policy PKG` -> {installed, candidate, origins[], official}"""
    inst = re.search(r"Installed:\s*(\S+)", text)
    cand = re.search(r"Candidate:\s*(\S+)", text)
    origins = []
    # version table: lines like "     500 http://deb.debian.org/debian trixie/main arm64 Packages"
    for m in re.finditer(r"^\s+(\d+)\s+(https?://\S+)", text, re.M):
        origins.append(m.group(2))
    installed = inst.group(1) if inst and inst.group(1) != "(none)" else ""
    candidate = cand.group(1) if cand and cand.group(1) != "(none)" else ""
    hosts = {re.sub(r"^https?://([^/]+).*", r"\1", o) for o in origins}
    return {"installed": installed, "candidate": candidate, "origins": sorted(hosts), "official": bool(hosts) and hosts <= set(OFFICIAL_ORIGINS)}


def package_status(pkg: str, runner) -> dict:
    if not re.fullmatch(r"[a-z0-9][a-z0-9+.-]{1,60}", pkg):
        raise ValueError("Ungültiger Paketname")
    rc, out = runner(["apt-cache", "policy", pkg])
    if rc == 127:
        return {"package": pkg, "available": False, "reason": "apt-cache nicht verfügbar"}
    p = parse_policy(out)
    return {"package": pkg, **p, "available": bool(p["candidate"]), "needs_install": bool(p["candidate"]) and not p["installed"],
            "reason": "" if p["candidate"] else "Paket in den konfigurierten Quellen nicht gefunden (apt update ausstehend?)"}


def analyse(inventory: dict, klog: str, runner, allowed: set[str]) -> dict:
    """Combine: kernel-log firmware failures, devices without driver, and package availability -> actionable findings."""
    findings = []
    for fw in missing_firmware(klog):
        pk = []
        for p in fw["packages"]:
            st = package_status(p, runner)
            st["installable"] = bool(st["available"] and st.get("official") and p in allowed)
            st["reboot"] = "Neustart oder erneutes Laden des Treibers erforderlich"
            pk.append(st)
        already = [p for p in pk if p.get("installed")]
        findings.append({"type": "firmware", "title": f"Firmware fehlt: {fw['file']}", "device": fw["device"], "detail": fw["line"], "packages": pk,
                         "state": "installed_reload" if already and len(already) == len(pk) else "missing" if pk else "unknown_file",
                         "advice": ("Die Firmware-Pakete sind installiert, die Datei fehlt aber trotzdem: Kernel-/Firmwareversion passt nicht (PiOS-System aktualisieren)." if already and len(already) == len(pk)
                                    else "Eines der folgenden Pakete aus den offiziellen Quellen installieren." if pk else "Für diese Datei ist kein offizielles Paket bekannt; PiOS installiert nichts automatisch.")})
    for pr in inventory.get("problems", []):
        findings.append({"type": "driver", "title": f"{pr['device']}: {pr['problem']}", "device": pr["device"], "detail": pr.get("detail", ""), "packages": [],
                         "state": "no_kernel_module" if pr.get("kernel_module_available") is False else "not_loaded" if pr.get("kernel_module_available") else "unknown",
                         "advice": "Für dieses Gerät gibt es im laufenden Kernel keinen Treiber. Ein Kernel-Update von Raspberry Pi OS kann Unterstützung bringen; PiOS lädt keine Treiber aus dem Internet nach."
                         if pr.get("kernel_module_available") is False else "Ein Treibermodul existiert; ein erneutes Einstecken oder 'Geräte neu erkennen' kann helfen." if pr.get("kernel_module_available") else "Treiberstatus nicht ermittelbar."})
    return {"findings": findings, "kernel": inventory.get("platform", {}).get("kernel", ""), "summary": {"firmware_missing": sum(1 for f in findings if f["type"] == "firmware" and f["state"] == "missing"),
                                                                                                   "drivers_missing": sum(1 for f in findings if f["type"] == "driver")}}
