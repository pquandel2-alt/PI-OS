"""Firewall engine: validate -> dry-run -> apply -> auto-revert unless confirmed -> persist."""
import ipaddress
import json
import logging
import subprocess
import threading
import time
from pathlib import Path

from . import TABLE
from .ruleset import ConfigError, FwConfig, expected_ports, render, render_sets

log = logging.getLogger("pios-firewall")
CONFIRM_SECONDS = 60


class FirewallError(Exception):
    def __init__(self, msg, code="error"):
        super().__init__(msg)
        self.code = code


class Nft:
    """Thin wrapper; `prefix` lets tests run nft inside a network namespace."""
    def __init__(self, prefix=("nft",)):
        self.prefix = list(prefix)

    def _run(self, args, stdin=None, timeout=15):
        try:
            r = subprocess.run([*self.prefix, *args], input=stdin, capture_output=True, text=True, timeout=timeout)
        except FileNotFoundError:
            raise FirewallError("nft ist nicht installiert", "no_nft") from None
        except subprocess.TimeoutExpired:
            raise FirewallError("nft antwortet nicht", "timeout") from None
        return r

    def check(self, script: str):
        r = self._run(["-c", "-f", "-"], script)
        if r.returncode != 0:
            raise FirewallError("Regelwerk ungültig: " + r.stderr.strip()[:300], "invalid_ruleset")

    def load(self, script: str):
        r = self._run(["-f", "-"], script)
        if r.returncode != 0:
            raise FirewallError("Regelwerk konnte nicht geladen werden: " + r.stderr.strip()[:300], "load_failed")

    def table_json(self):
        r = self._run(["-j", "list", "table", "inet", TABLE])
        if r.returncode != 0:
            return None
        return json.loads(r.stdout)


def detect_lan() -> tuple[list, list]:
    """On-link prefixes of this host: global IPv6 /64s (ISP prefixes are not covered by the ULA range) and IPv4 subnets."""
    try:
        r = subprocess.run(["ip", "-j", "addr", "show", "scope", "global"], capture_output=True, text=True, timeout=5)
        data = json.loads(r.stdout or "[]")
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return [], []
    v4, v6 = set(), set()
    for ifc in data:
        for a in ifc.get("addr_info", []):
            try:
                n = ipaddress.ip_network(f"{a['local']}/{a['prefixlen']}", strict=False)
            except (ValueError, KeyError):
                continue
            if n.prefixlen == 0:
                continue
            (v4 if n.version == 4 else v6).add(str(n))
    return sorted(v4), sorted(v6)


class Firewall:
    def __init__(self, nft: Nft, state: Path, detect=detect_lan, confirm_seconds=CONFIRM_SECONDS):
        self.nft, self.state, self.detect, self.confirm_seconds = nft, Path(state), detect, confirm_seconds
        self.state.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lock = threading.RLock()
        self.pending = None            # {"cfg": FwConfig, "deadline": monotonic, "timer": Timer}
        self.last_event = None
        self.loaded_ok = False

    # ---- persistence ----
    def _cfg_path(self): return self.state / "config.json"

    def persisted(self) -> FwConfig:
        try:
            return FwConfig.from_dict(json.loads(self._cfg_path().read_text()))
        except (OSError, ValueError, ConfigError):
            return FwConfig()

    def _persist(self, cfg: FwConfig):
        tmp = self._cfg_path().with_suffix(".tmp")
        tmp.write_text(json.dumps(cfg.to_dict(), indent=2))
        tmp.replace(self._cfg_path())

    def script_for(self, cfg: FwConfig) -> str:
        lan4, lan6 = self.detect()
        return render(cfg, lan4, lan6)

    # ---- operations ----
    def boot(self):
        """Load the persisted (confirmed) policy. Falls back to the built-in default; an unconfirmed change never survives."""
        with self.lock:
            for cfg in (self.persisted(), FwConfig()):
                try:
                    script = self.script_for(cfg)
                    self.nft.check(script); self.nft.load(script)
                    self.loaded_ok = True
                    log.info("firewall loaded (ssh=%s scope=%s)", cfg.ssh, cfg.web_scope)
                    return self.status()
                except FirewallError as e:
                    log.error("firewall load failed: %s", e)
            self.loaded_ok = False
            raise FirewallError("Firewall konnte nicht geladen werden", "boot_failed")

    def preview(self, raw: dict) -> dict:
        cfg = FwConfig.from_dict(raw)
        script = self.script_for(cfg)
        self.nft.check(script)
        return {"config": cfg.to_dict(), "script": script, "expected_ports": expected_ports(cfg)}

    def apply(self, raw: dict) -> dict:
        with self.lock:
            if self.pending:
                raise FirewallError("Eine Änderung wartet noch auf Bestätigung", "pending")
            cfg = FwConfig.from_dict(raw)
            script = self.script_for(cfg)
            self.nft.check(script)                       # validate before touching the live ruleset
            self.nft.load(script)                        # atomic transaction in the kernel
            timer = threading.Timer(self.confirm_seconds, self._expire)
            timer.daemon = True
            self.pending = {"cfg": cfg, "deadline": time.monotonic() + self.confirm_seconds, "timer": timer}
            timer.start()
            log.warning("firewall change applied, revert in %ss unless confirmed", self.confirm_seconds)
            return self.status()

    def confirm(self) -> dict:
        with self.lock:
            if not self.pending:
                raise FirewallError("Keine Änderung zu bestätigen", "nothing_pending")
            self.pending["timer"].cancel()
            self._persist(self.pending["cfg"])
            self.pending = None
            self.last_event = {"kind": "confirmed", "time": int(time.time())}
            log.warning("firewall change confirmed and persisted")
            return self.status()

    def revert(self) -> dict:
        with self.lock:
            if self.pending:
                self.pending["timer"].cancel()
                self.pending = None
            cfg = self.persisted()
            script = self.script_for(cfg)
            self.nft.check(script); self.nft.load(script)
            self.last_event = {"kind": "reverted", "time": int(time.time())}
            log.warning("firewall reverted to the last confirmed policy")
            return self.status()

    def _expire(self):
        with self.lock:
            if not self.pending:
                return
            try:
                self.revert()
                self.last_event = {"kind": "auto_reverted", "time": int(time.time())}
            except FirewallError as e:
                log.error("auto-revert failed: %s", e)

    def maintain(self):
        """Refresh the address sets if the on-link networks changed (e.g. new IPv6 prefix). No policy change."""
        with self.lock:
            if self.pending:
                return False
            cfg = self.persisted()
            lan4, lan6 = self.detect()
            want = render_sets(cfg, lan4, lan6)
            if want == getattr(self, "_last_sets", None):
                return False
            try:
                self.nft.load(want)
                self._last_sets = want
                return True
            except FirewallError as e:
                log.error("set refresh failed: %s", e)
                return False

    # ---- verification of the *live* kernel state ----
    def verify_live(self, cfg: FwConfig) -> list[str]:
        """Problems found when comparing the loaded ruleset with the invariants of `cfg` (empty list = healthy)."""
        try:
            data = self.nft.table_json()
        except FirewallError as e:
            return [str(e)]
        if data is None:
            return ["Tabelle inet pios_fw ist nicht geladen: der Rechner ist nicht durch die PiOS-Firewall geschützt"]
        items = [x for x in data.get("nftables", [])]
        chains = {x["chain"]["name"]: x["chain"] for x in items if "chain" in x}
        problems = []
        for name, pol in (("input", "drop"), ("forward", "drop")):
            ch = chains.get(name)
            if not ch:
                problems.append(f"Kette {name} fehlt")
            elif ch.get("policy") != pol or ch.get("hook") != name:
                problems.append(f"Kette {name}: Policy ist {ch.get('policy')}, erwartet {pol}")
        tcp, udp = set(), set()
        for x in items:
            rule = x.get("rule")
            if not rule or rule.get("chain") != "input":
                continue
            if not any("accept" in e for e in rule["expr"]):
                continue
            for e in rule["expr"]:
                m = e.get("match")
                if m and m.get("left", {}).get("payload", {}).get("field") == "dport":
                    proto = m["left"]["payload"]["protocol"]
                    right = m["right"]
                    ports = right if isinstance(right, list) else [right]
                    (tcp if proto == "tcp" else udp if proto == "udp" else set()).update(p for p in ports if isinstance(p, int))
        exp = expected_ports(cfg)
        if tcp != set(exp["tcp"]):
            problems.append(f"Offene TCP-Ports {sorted(tcp)} weichen von der Konfiguration {exp['tcp']} ab")
        if udp != set(exp["udp"]):
            problems.append(f"Offene UDP-Ports {sorted(udp)} weichen von der Konfiguration {exp['udp']} ab")
        return problems

    def status(self) -> dict:
        with self.lock:
            cfg = self.persisted()
            pend = None
            if self.pending:
                pend = {"config": self.pending["cfg"].to_dict(), "seconds_left": max(0, round(self.pending["deadline"] - time.monotonic()))}
            live_cfg = self.pending["cfg"] if self.pending else cfg
            problems = self.verify_live(live_cfg)
            return {"api": 1, "active": not problems, "problems": problems, "config": cfg.to_dict(), "pending": pend,
                    "expected_ports": expected_ports(live_cfg), "last_event": self.last_event, "confirm_seconds": self.confirm_seconds,
                    "ipv6": True}
