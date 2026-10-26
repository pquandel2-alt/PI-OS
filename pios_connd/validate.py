"""Strict input validation. Everything that reaches D-Bus, a file or a subprocess goes through here first."""
import re

IFACE = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")
MAC = re.compile(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
PKG = re.compile(r"^[a-z0-9][a-z0-9+.-]{1,60}$")
# ISO 3166-1 alpha-2 codes accepted as Wi-Fi regulatory domains (regdb countries; "00" world domain is deliberately excluded)
COUNTRIES = set("""AD AE AF AG AI AL AM AO AR AS AT AU AW AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BW BY BZ CA CD CF CG CH CI CK CL CM CN CO CR CU CV CW CY CZ
DE DJ DK DM DO DZ EC EE EG ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GT GU GW GY HK HN HR HT HU ID IE IL IM IN IQ IR IS IT JE JM JO JP KE KG KH
KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE
PF PG PH PK PL PM PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TG TH TJ TL TM TN TO TR TT TV TW TZ UA UG US UY UZ VA
VC VE VG VI VN VU WF WS YE YT ZA ZM ZW""".split())


class InvalidInput(ValueError):
    pass


def ssid(value) -> bytes:
    """An SSID is 1-32 *bytes*; control characters are refused (they would corrupt logs/UI)."""
    if not isinstance(value, str) or not value:
        raise InvalidInput("SSID fehlt")
    raw = value.encode("utf-8")
    if len(raw) > 32:
        raise InvalidInput("Eine SSID darf höchstens 32 Bytes lang sein")
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise InvalidInput("SSID enthält Steuerzeichen")
    return raw


def psk(value) -> str:
    """WPA2/WPA3 personal: 8-63 printable ASCII characters, or exactly 64 hex digits (raw PSK)."""
    if not isinstance(value, str):
        raise InvalidInput("Passwort fehlt")
    if len(value) == 64 and re.fullmatch(r"[0-9A-Fa-f]{64}", value):
        return value
    if not 8 <= len(value) <= 63:
        raise InvalidInput("Das WLAN-Passwort muss 8 bis 63 Zeichen lang sein")
    if not all(32 <= ord(c) < 127 for c in value):
        raise InvalidInput("Das WLAN-Passwort darf nur druckbare ASCII-Zeichen enthalten")
    return value


def iface(value) -> str:
    if not isinstance(value, str) or not IFACE.match(value):
        raise InvalidInput("Ungültiger Schnittstellenname")
    return value


def mac(value) -> str:
    v = str(value).upper()
    if not MAC.match(v):
        raise InvalidInput("Ungültige Geräteadresse")
    return v


def uuid(value) -> str:
    if not isinstance(value, str) or not UUID.match(value):
        raise InvalidInput("Ungültige Verbindungs-ID")
    return value


def country(value) -> str:
    v = str(value).upper()
    if v not in COUNTRIES:
        raise InvalidInput("Unbekannter Ländercode (zwei Buchstaben, z. B. DE)")
    return v


def boolean(value, name="Wert") -> bool:
    if not isinstance(value, bool):
        raise InvalidInput(f"{name} muss true oder false sein")
    return value


def seconds(value, lo=5, hi=120, name="Dauer") -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not lo <= value <= hi:
        raise InvalidInput(f"{name} muss zwischen {lo} und {hi} Sekunden liegen")
    return value
