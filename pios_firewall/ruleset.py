"""Firewall policy as data -> nftables script. Clients can only choose among a few validated options; they can never
submit nftables text. The generated ruleset is default-deny for inbound traffic."""
import ipaddress
from dataclasses import asdict, dataclass, field

from . import TABLE

PRIVATE4 = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10"]
PRIVATE6 = ["fc00::/7", "fe80::/10"]
MAX_CIDRS = 16
KEYS = {"web_scope", "web_cidrs", "ssh", "mdns", "ping"}


class ConfigError(ValueError):
    pass


@dataclass
class FwConfig:
    web_scope: str = "lan"                 # "lan": private + on-link networks | "custom": only web_cidrs
    web_cidrs: list = field(default_factory=list)
    ssh: bool = False                      # tcp/22, same source scope as the web UI
    mdns: bool = True                      # pios.local
    ping: bool = True                      # rate-limited echo-request from the LAN scope

    @classmethod
    def from_dict(cls, d: dict) -> "FwConfig":
        if not isinstance(d, dict):
            raise ConfigError("Konfiguration muss ein Objekt sein")
        unknown = set(d) - KEYS
        if unknown:
            raise ConfigError(f"Unbekannte Optionen: {sorted(unknown)}")
        c = cls(**{k: d[k] for k in d})
        if c.web_scope not in ("lan", "custom"):
            raise ConfigError("web_scope muss 'lan' oder 'custom' sein")
        for k in ("ssh", "mdns", "ping"):
            if not isinstance(getattr(c, k), bool):
                raise ConfigError(f"{k} muss true/false sein")
        if not isinstance(c.web_cidrs, list) or len(c.web_cidrs) > MAX_CIDRS:
            raise ConfigError(f"web_cidrs: höchstens {MAX_CIDRS} Netze")
        norm = []
        for x in c.web_cidrs:
            try:
                n = ipaddress.ip_network(str(x), strict=False)
            except ValueError:
                raise ConfigError(f"Ungültiges Netz: {str(x)[:40]!r}") from None
            if n.prefixlen == 0:
                raise ConfigError("Ein Netz mit Präfixlänge 0 würde die gesamte Welt freigeben")
            norm.append(str(n))
        c.web_cidrs = sorted(set(norm))
        if c.web_scope == "custom" and not c.web_cidrs:
            raise ConfigError("web_scope 'custom' benötigt mindestens ein Netz")
        return c

    def to_dict(self) -> dict:
        return asdict(self)


def _set(name, typ, elements):
    return f"  set {name} {{ type {typ}; flags interval; auto-merge; elements = {{ {', '.join(elements)} }} }}\n" if elements else f"  set {name} {{ type {typ}; flags interval; auto-merge; }}\n"


def sources(cfg: FwConfig, lan4: list, lan6: list) -> tuple[list, list]:
    if cfg.web_scope == "custom":
        n = [ipaddress.ip_network(c) for c in cfg.web_cidrs]
        return [str(x) for x in n if x.version == 4], [str(x) for x in n if x.version == 6]
    return sorted(set(PRIVATE4 + lan4)), sorted(set(PRIVATE6 + lan6))


def render(cfg: FwConfig, lan4=(), lan6=()) -> str:
    s4, s6 = sources(cfg, list(lan4), list(lan6))
    out = [f"add table inet {TABLE}\ndelete table inet {TABLE}\ntable inet {TABLE} {{\n"]
    out.append(_set("allowed4", "ipv4_addr", s4))
    out.append(_set("allowed6", "ipv6_addr", s6))
    out.append("  chain input {\n    type filter hook input priority filter; policy drop;\n")
    out.append('    ct state invalid drop\n    ct state { established, related } accept\n    iif "lo" accept\n')
    out.append("    # IPv6 cannot work without these ICMPv6 types (neighbour discovery, path MTU, multicast listener)\n")
    out.append("    ip6 nexthdr ipv6-icmp icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem,"
               " nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, mld-listener-query, mld-listener-report, mld2-listener-report } accept\n")
    out.append("    icmp type { destination-unreachable, time-exceeded, parameter-problem } accept\n")
    if cfg.ping:
        out.append("    ip saddr @allowed4 icmp type echo-request limit rate 5/second accept\n")
        out.append("    ip6 saddr @allowed6 icmpv6 type echo-request limit rate 5/second accept\n")
    out.append("    # DHCP / DHCPv6 client replies\n    udp sport 67 udp dport 68 accept\n    ip6 saddr fe80::/10 udp sport 547 udp dport 546 accept\n")
    if cfg.mdns:
        out.append("    ip saddr @allowed4 udp dport 5353 accept\n    ip6 saddr @allowed6 udp dport 5353 accept\n")
    out.append("    # PiOS web interface\n    ip saddr @allowed4 tcp dport 80 ct state new accept\n    ip6 saddr @allowed6 tcp dport 80 ct state new accept\n")
    if cfg.ssh:
        out.append("    ip saddr @allowed4 tcp dport 22 ct state new accept\n    ip6 saddr @allowed6 tcp dport 22 ct state new accept\n")
    out.append('    limit rate 3/minute log prefix "pios-fw drop: " level info\n')
    out.append("  }\n  chain forward {\n    type filter hook forward priority filter; policy drop;\n  }\n")
    out.append("  chain output {\n    type filter hook output priority filter; policy accept;\n  }\n}\n")
    return "".join(out)


def render_sets(cfg: FwConfig, lan4, lan6) -> str:
    """Only the two address sets (used when the on-link prefixes change; atomic, no policy change)."""
    s4, s6 = sources(cfg, list(lan4), list(lan6))
    lines = [f"flush set inet {TABLE} allowed4", f"flush set inet {TABLE} allowed6"]
    if s4:
        lines.append(f"add element inet {TABLE} allowed4 {{ {', '.join(s4)} }}")
    if s6:
        lines.append(f"add element inet {TABLE} allowed6 {{ {', '.join(s6)} }}")
    return "\n".join(lines) + "\n"


def expected_ports(cfg: FwConfig) -> dict:
    return {"tcp": sorted({80} | ({22} if cfg.ssh else set())), "udp": sorted({68, 546} | ({5353} if cfg.mdns else set()))}  # 68/546: DHCP(v6) client replies from port 67/547 only
