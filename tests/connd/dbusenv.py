"""A private system bus with python-dbusmock's NetworkManager / BlueZ stand-ins (real D-Bus, simulated daemons)."""
import os
import subprocess
import time

import dbus
import dbusmock
import pytest


class Bus(dbusmock.DBusTestCase):
    pass


@pytest.fixture(scope="session")
def system_bus():
    if not os.path.exists("/usr/bin/dbus-daemon"):
        pytest.skip("dbus-daemon not installed")
    Bus.start_system_bus()
    yield Bus
    Bus.stop_dbus(Bus.system_bus_pid) if hasattr(Bus, "stop_dbus") else None


@pytest.fixture()
def nm_mock(system_bus):
    p, obj = system_bus.spawn_server_template("networkmanager", {"NetworkingEnabled": True, "WirelessEnabled": True, "Connectivity": 4}, stdout=subprocess.DEVNULL)
    time.sleep(0.2)
    mock = dbus.Interface(obj, dbusmock.MOCK_IFACE)
    yield type("NM", (), {"proc": p, "obj": obj, "mock": mock, "bus": dbus.SystemBus(), "nm_mock_iface": mock})
    p.terminate(); p.wait()


class _Rec:
    """Proxy that records D-Bus method calls (to assert exactly what PiOS sends, e.g. where the password goes) and optionally fakes them."""
    def __init__(self, real, log, fake):
        self._real, self._log, self._fake = real, log, fake

    def __getattr__(self, name):
        target = getattr(self._real, name)
        if not callable(target):
            return target

        def call(*a, **kw):
            self._log.append((name, a))
            if self._fake and name in self._fake:
                return self._fake[name]
            return target(*a, **kw)
        return call


def recording(client, fake=None):
    """Wrap an NMClient so every `_obj(...)` proxy records calls; returns the call log."""
    log = []
    orig = client._obj
    client._obj = lambda path, iface=None: _Rec(orig(path, iface), log, fake)
    return log
