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
    dbus.SystemBus().set_exit_on_disconnect(False)
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


@pytest.fixture(scope="session")
def bt_bus(system_bus):
    """ONE private connection with a GLib main loop for the whole session (agent calls from BlueZ arrive here)."""
    import threading
    from dbus.mainloop.glib import DBusGMainLoop
    from gi.repository import GLib
    loop = GLib.MainLoop()
    bus = dbus.SystemBus(mainloop=DBusGMainLoop(), private=True)
    bus.set_exit_on_disconnect(False)
    threading.Thread(target=loop.run, daemon=True).start()
    yield bus
    loop.quit()


@pytest.fixture(scope="session")
def bt_server(system_bus):
    p, obj = system_bus.spawn_server_template("bluez5", {}, stdout=open(os.environ.get("PIOS_MOCKLOG", os.devnull), "w"))
    time.sleep(0.2)
    yield obj
    p.terminate(); p.wait()


@pytest.fixture()
def bt_mock(bt_server, bt_bus):
    """BlueZ stand-in (one process for the session, adapters/devices reset per test)."""
    from gi.repository import GLib
    obj = bt_server
    mock = dbus.Interface(obj, dbusmock.MOCK_IFACE)
    adapter = dbus.Interface(obj, "org.bluez.Mock")

    def glib_call(fn, *a):
        GLib.idle_add(lambda: (fn(*a), False)[1])

    def device_mock(path):
        return dbus.Interface(bt_bus.get_object("org.bluez", path), dbusmock.MOCK_IFACE)

    yield type("BT", (), {"obj": obj, "mock": mock, "bluez": adapter, "bus": bt_bus, "glib_call": staticmethod(glib_call), "device_mock": staticmethod(device_mock),
                          "agent_name": bt_bus.get_unique_name()})
    for name in ("hci0", "hci1"):
        try:
            adapter.RemoveAdapterWithDevices(name)
        except dbus.DBusException:
            pass
