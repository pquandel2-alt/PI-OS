"""Input diagnosis: each scenario breaks exactly one layer between the USB receiver and the compositor; the verdict must name that layer."""
import os
import struct

import pytest

from pios_connd import inputdiag as d
from tests.connd.fakehw import LIBINPUT_OK, FakeHW, full_runner, kiosk


@pytest.fixture()
def hw(tmp_path):
    h = FakeHW(tmp_path)
    h.drivers(); h.usb_hub(); h.usb_hid(); h.mouse(); h.keyboard(); h.cage(opens=(4, 5), env={"WLR_NO_HARDWARE_CURSORS": "1"})
    return h


def run(hw, runner=None, **kw):
    return d.diagnose(hw.r, runner or full_runner(), kiosk(gids=[os.getgid()]))


def state(res, sid):
    return next(s["state"] for s in res["stages"] if s["id"] == sid)


def test_healthy_usb_receiver_passes_every_layer(hw):
    res = run(hw)
    assert [s["state"] for s in res["stages"] if s["state"] not in ("ok",)] == []
    assert res["verdict"]["state"] == "ok" and res["devices"]["pointers"][0]["name"].startswith("Logitech")


def test_no_usb_hid_device_at_all(hw):
    import shutil
    shutil.rmtree(hw.root / "sys/bus/usb/devices/1-1"); shutil.rmtree(hw.root / "sys/bus/usb/devices/1-1:1.0", ignore_errors=True)
    (hw.root / "proc/bus/input/devices").write_text("")
    res = run(hw)
    assert res["verdict"]["state"] == "fail" and res["verdict"]["stage"] == "usb" and "Funkempfänger" in res["verdict"]["cause"]


def test_usb_hid_kernel_driver_missing(hw):
    import shutil
    shutil.rmtree(hw.root / "sys/bus/usb/drivers/usbhid")
    res = run(hw)
    assert state(res, "kernel") == "fail" and res["verdict"]["stage"] == "kernel" and "usbhid" in res["verdict"]["cause"]


def test_receiver_seen_but_no_driver_bound(tmp_path):
    h = FakeHW(tmp_path); h.drivers(); h.usb_hid(bound=False)
    res = d.diagnose(h.r, full_runner(), kiosk())
    assert res["verdict"]["stage"] == "binding" and "kein treiber" in res["verdict"]["cause"].lower()


def test_driver_bound_but_kernel_created_no_input_device(tmp_path):
    h = FakeHW(tmp_path); h.drivers(); h.usb_hid()
    res = d.diagnose(h.r, full_runner(), kiosk())
    assert res["verdict"]["stage"] == "input" and "kein Eingabegerät entstanden" in res["verdict"]["cause"]


def test_udev_did_not_classify_the_device(hw):
    (hw.root / "udev/c13:68").unlink()
    res = run(hw)
    assert res["verdict"]["stage"] == "udev" and "Logitech" in res["verdict"]["cause"]


def test_libinput_does_not_see_the_device(hw):
    res = run(hw, full_runner(libinput="Device:  Something Else\nKernel: /dev/input/event9\nCapabilities: pointer\n"))
    assert res["verdict"]["stage"] == "libinput"


def test_libinput_tools_missing_is_unknown_not_ok(hw):
    from tests.connd.fakehw import Runner
    base = full_runner()
    r = Runner(**{"|".join(k): v for k, v in base.cmds.items() if k[0] != "libinput"})
    res = run(hw, r)
    assert state(res, "libinput") == "unknown"


def test_kiosk_running_without_logind_session(hw):
    res = run(hw, full_runner(sessions=""))
    assert res["verdict"]["stage"] == "session" and "keine Sitzung" in res["verdict"]["cause"]


def test_inactive_logind_session_blocks_input(hw):
    res = run(hw, full_runner(show="Active=no\nState=online\nType=tty\nSeat=seat0\nVTNr=1\nClass=user\n"))
    assert res["verdict"]["stage"] == "session" and "nicht aktiv" in res["verdict"]["cause"]


def test_compositor_opened_no_input_devices(hw):
    import shutil
    shutil.rmtree(hw.root / "proc/4242"); hw.cage(opens=(), env={"WLR_NO_HARDWARE_CURSORS": "1"})
    res = run(hw)
    assert res["verdict"]["stage"] == "compositor" and "KEIN Eingabegerät geöffnet" in res["verdict"]["cause"]


def test_compositor_has_other_devices_but_not_the_mouse(hw):
    import shutil
    shutil.rmtree(hw.root / "proc/4242"); hw.cage(opens=(5,), env={"WLR_NO_HARDWARE_CURSORS": "1"})
    res = run(hw)
    assert res["verdict"]["stage"] == "compositor" and "event4" in res["verdict"]["cause"]


def test_kiosk_service_inactive_is_reported_not_failed(hw):
    import shutil
    shutil.rmtree(hw.root / "proc/4242")
    res = run(hw, full_runner(unit="inactive\n"))
    assert state(res, "session") == "warn" and res["verdict"]["state"] != "ok" and "Monitor" in next(s for s in res["stages"] if s["id"] == "session")["detail"]


@pytest.mark.parametrize("env,expect", [({"WLR_NO_HARDWARE_CURSORS": "0"}, "warn"), ({}, "warn"), ({"WLR_NO_HARDWARE_CURSORS": "1"}, "ok")])
def test_hardware_cursor_is_flagged_as_likely_cause_of_an_invisible_pointer(hw, env, expect):
    import shutil
    shutil.rmtree(hw.root / "proc/4242"); hw.cage(opens=(4, 5), env=env)
    res = run(hw)
    assert state(res, "cursor") == expect
    if expect == "warn":
        assert res["verdict"]["state"] == "warn" and "Cursor" in res["verdict"]["cause"]


def test_permission_denied_on_node_is_a_warning_when_logind_hands_out_devices(hw):
    node = hw.root / "dev/input/event4"; os.chmod(node, 0o600)
    res = d.diagnose(hw.r, full_runner(), kiosk(uid=os.getuid() + 1, gids=[]))     # neither owner nor group
    assert state(res, "access") == "warn" and res["verdict"]["state"] == "ok", "device access comes via the logind session, direct read is not required"


def test_world_readable_node_is_readable(tmp_path):
    p = tmp_path / "ev"; p.write_text(""); os.chmod(p, 0o644)
    assert d.can_read(p, 12345, {12345})[0] is True
    os.chmod(p, 0o600)
    assert d.can_read(p, os.getuid() + 1, {os.getgid() + 1})[0] is False
    assert d.can_read(tmp_path / "missing", 1, {1})[0] is None


def test_acl_for_the_session_user_grants_access(tmp_path, monkeypatch):
    p = tmp_path / "ev"; p.write_text(""); os.chmod(p, 0o660)
    def acl(entries):
        return struct.pack("<I", 2) + b"".join(struct.pack("<HHI", t, perm, ident) for t, perm, ident in entries)
    raw = acl([(0x01, 6, 0xFFFFFFFF), (0x02, 6, 7777), (0x04, 6, 0xFFFFFFFF), (0x10, 6, 0xFFFFFFFF), (0x20, 0, 0xFFFFFFFF)])
    assert d.parse_acl(raw)[1] == ("user", 7777, 6)
    monkeypatch.setattr(os, "getxattr", lambda path, name: raw)
    ok, why = d.can_read(p, 7777, {7777})
    assert ok is True and "ACL" in why
    assert d.can_read(p, 8888, {8888})[0] is False


def test_bluetooth_hid_mouse_is_diagnosed_without_usb(tmp_path):
    h = FakeHW(tmp_path); h.drivers(); h.mouse(event=6, name="MX Anywhere 3", vendor="046d", product="b025", bus="0005", uniq="aa:bb:cc:dd:ee:ff"); h.cage(opens=(6,), env={"WLR_NO_HARDWARE_CURSORS": "1"})
    res = d.diagnose(h.r, full_runner(libinput=LIBINPUT_OK.replace("event4", "event6")), kiosk())
    assert state(res, "usb") == "warn" and "Bluetooth" in next(s for s in res["stages"] if s["id"] == "usb")["detail"]
    assert res["devices"]["pointers"][0]["transport"] == "bluetooth" and res["verdict"]["state"] == "ok"


def test_kernel_log_hints(hw):
    res = run(hw, full_runner(klog="usb 1-1: device descriptor read/64, error -71\nusb usb1-port2: over-current condition\n"))
    assert any("Überstrom" in h for h in res["hints"]) and any("Kommunikationsfehler" in h for h in res["hints"])


def test_missing_kiosk_user_is_reported(hw):
    res = d.diagnose(hw.r, full_runner(), None)
    assert state(res, "access") == "fail" and "pios-kiosk" in res["verdict"]["cause"]
