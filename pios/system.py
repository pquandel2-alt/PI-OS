"""System metrics for NOVA Monitor and the orb."""
import os
import shutil
import socket
import time
from pathlib import Path

import psutil
from fastapi import APIRouter, Depends

from . import __version__, config
from .security import current_user

router = APIRouter(prefix="/api")
psutil.cpu_percent(None)  # prime the delta counter


def cpu_temp() -> float | None:
    try:
        for values in psutil.sensors_temperatures().values():
            for v in values:
                return round(v.current, 1)
    except (AttributeError, OSError):
        pass
    p = Path("/sys/class/thermal/thermal_zone0/temp")
    try:
        return round(int(p.read_text()) / 1000, 1)
    except (OSError, ValueError):
        return None


def network() -> dict:
    stats, addrs = psutil.net_if_stats(), psutil.net_if_addrs()
    ifaces = []
    for name, st in stats.items():
        if name == "lo" or name.startswith(("docker", "veth", "br-")):
            continue
        ip4 = next((a.address for a in addrs.get(name, []) if a.family == socket.AF_INET), None)
        ifaces.append({"name": name, "up": st.isup, "speed": st.speed, "ip": ip4})
    io = psutil.net_io_counters()
    return {"hostname": socket.gethostname(), "interfaces": ifaces,
            "online": any(i["up"] and i["ip"] for i in ifaces),
            "rx": io.bytes_recv, "tx": io.bytes_sent}


def summary() -> dict:
    mem = psutil.virtual_memory()
    du = shutil.disk_usage(config.DATA)
    try:
        load = [round(x, 2) for x in os.getloadavg()]
    except OSError:
        load = []
    return {
        "version": __version__, "time": int(time.time()),
        "cpu": psutil.cpu_percent(None), "cores": psutil.cpu_count() or 1, "load": load,
        "ram": {"percent": mem.percent, "used": mem.used, "total": mem.total},
        "disk": {"percent": round(du.used / du.total * 100, 1), "used": du.used, "total": du.total, "free": du.free},
        "temp": cpu_temp(), "uptime": int(time.time() - psutil.boot_time()), "net": network(),
    }


@router.get("/system")
def system(u=Depends(current_user)):
    return summary()
