"""Builds a fake /sys, /proc, /dev and udev database for the hardware tests (no real hardware, no root needed)."""
import os
import struct
from pathlib import Path

from pios_connd.hw import Roots

INPUT_BLOCK = """I: Bus={bus} Vendor={vendor} Product={product} Version=0111
N: Name="{name}"
P: Phys={phys}
S: Sysfs=/devices/platform/usb/{sysfs}
U: Uniq={uniq}
H: Handlers={handlers}
B: PROP=0
B: EV={ev}
B: KEY=1f0000 0 0 0 0
B: REL={rel}
"""


class FakeHW:
    def __init__(self, tmp: Path):
        self.root = tmp
        self.r = Roots(sys=tmp / "sys", proc=tmp / "proc", dev=tmp / "dev", udev=tmp / "udev")
        for d in ("sys/bus/usb/devices", "proc/bus/input", "dev/input", "udev", "sys/class/net", "sys/class/rfkill", "sys/class/bluetooth", "sys/class/drm", "sys/block", "proc/asound"):
            (tmp / d).mkdir(parents=True, exist_ok=True)
        self.inputs = []
        self.udev_extra = {}

    def w(self, rel, text):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        return p

    # -- USB
    def drivers(self, usbhid=True, hid_generic=True):
        if usbhid:
            (self.root / "sys/bus/usb/drivers/usbhid").mkdir(parents=True, exist_ok=True)
        if hid_generic:
            (self.root / "sys/bus/hid/drivers/hid-generic").mkdir(parents=True, exist_ok=True)

    def usb_hid(self, name="1-1", vendor="046d", product="c52b", prod="USB Receiver", manu="Logitech", protocol="02", bound=True, subclass="01", klass="03"):
        d = f"sys/bus/usb/devices/{name}"
        for f, v in (("idVendor", vendor), ("idProduct", product), ("manufacturer", manu), ("product", prod), ("bDeviceClass", "00"), ("speed", "12"), ("busnum", "1"), ("devnum", "2")):
            self.w(f"{d}/{f}", v + "\n")
        i = f"{d}:1.0"
        for f, v in (("bInterfaceClass", klass), ("bInterfaceSubClass", subclass), ("bInterfaceProtocol", protocol), ("modalias", f"usb:v{vendor.upper()}p{product.upper()}d0111dc00dsc00dp00ic03isc01ip02in00")):
            self.w(f"{d}:1.0/{f}", v + "\n")
        if bound:
            target = self.root / "sys/bus/usb/drivers/usbhid"
            target.mkdir(parents=True, exist_ok=True)
            os.symlink(target, self.root / i / "driver")

    def usb_hub(self):
        self.w("sys/bus/usb/devices/usb1/idVendor", "1d6b\n"); self.w("sys/bus/usb/devices/usb1/idProduct", "0002\n"); self.w("sys/bus/usb/devices/usb1/bDeviceClass", "09\n")

    # -- input devices
    def mouse(self, event=4, name="Logitech USB Receiver", vendor="046d", product="c52b", bus="0003", uniq="", udev=True, node_mode=0o660):
        self.inputs.append(INPUT_BLOCK.format(bus=bus, vendor=vendor, product=product, name=name, phys="usb-1/input0", sysfs=f"input{event}", uniq=uniq,
                                              handlers=f"mouse0 event{event}", ev="17", rel="143"))
        self.w("proc/bus/input/devices", "\n".join(self.inputs))
        node = self.root / f"dev/input/event{event}"
        node.write_text("")
        os.chmod(node, node_mode)
        if udev:
            self.w(f"udev/c13:{64 + event}", "I:1\nE:ID_INPUT=1\nE:ID_INPUT_MOUSE=1\nE:ID_SEAT=seat0\nG:seat\nG:uaccess\nQ:seat\nQ:uaccess\n")

    def keyboard(self, event=5, name="USB Keyboard"):
        self.inputs.append(INPUT_BLOCK.format(bus="0003", vendor="04d9", product="0006", name=name, phys="usb-1/input1", sysfs=f"input{event}", uniq="", handlers=f"sysrq kbd leds event{event}", ev="120013", rel="0"))
        self.w("proc/bus/input/devices", "\n".join(self.inputs))
        (self.root / f"dev/input/event{event}").write_text("")
        self.w(f"udev/c13:{64 + event}", "E:ID_INPUT=1\nE:ID_INPUT_KEYBOARD=1\n")

    # -- compositor process
    def cage(self, pid=4242, opens=(4,), env=None, dri=1):
        p = self.root / f"proc/{pid}"
        (p / "fd").mkdir(parents=True, exist_ok=True)
        (p / "comm").write_text("cage\n")
        n = 3
        for e in opens:
            os.symlink(f"/dev/input/event{e}", p / "fd" / str(n)); n += 1
        for _ in range(dri):
            os.symlink("/dev/dri/card0", p / "fd" / str(n)); n += 1
        (p / "environ").write_bytes(b"\0".join(f"{k}={v}".encode() for k, v in (env or {}).items()) + b"\0")


def kiosk(gids=(), uid=7777):
    mygid = os.getgid()
    return {"user": "pios-kiosk", "uid": uid, "gids": {9999, *gids}, "groups": ["pios-kiosk"], "mygid": mygid}


class Runner:
    """Scripted external commands."""
    def __init__(self, **cmds):
        self.cmds = {tuple(k.split("|")): v for k, v in cmds.items()}
        self.calls = []

    def __call__(self, cmd, timeout=8):
        self.calls.append(cmd)
        return self.cmds.get(tuple(cmd), (127, ""))


LIBINPUT_OK = """Device:           Logitech USB Receiver
Kernel:           /dev/input/event4
Group:            3
Seat:             seat0, default
Capabilities:     pointer
Tap-to-click:     n/a

Device:           USB Keyboard
Kernel:           /dev/input/event5
Group:            4
Seat:             seat0, default
Capabilities:     keyboard
"""
SESSION_OK = "c1 7777 pios-kiosk seat0 tty1\n"
SHOW_OK = "Active=yes\nState=active\nType=tty\nSeat=seat0\nVTNr=1\nClass=user\n"


def full_runner(libinput=LIBINPUT_OK, sessions=SESSION_OK, show=SHOW_OK, unit="active\n", klog=""):
    return Runner(**{"libinput|list-devices": (0, libinput), "loginctl|list-sessions|--no-legend|--no-pager": (0, sessions),
                     "loginctl|show-session|c1|-p|Active|-p|State|-p|Type|-p|Seat|-p|VTNr|-p|Class": (0, show), "systemctl|is-active|pios-kiosk.service": (0, unit),
                     "journalctl|-k|-b|--no-pager|-o|cat|-n|600": (0, klog)})
