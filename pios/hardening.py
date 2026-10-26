"""HTTP hardening as pure ASGI middleware (no buffering, safe with Server-Sent Events).

* HostGuard    – only accepts Host headers that name this device (blocks DNS-rebinding and host-header attacks)
* BodyLimit    – rejects oversized request bodies *before* the framework parses/spools them
* SecureHeaders – CSP, permissions policy, cross-origin isolation headers on every response
"""
import ipaddress
import os
import socket

from . import config

DEFAULT_CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; "
               "media-src 'self'; connect-src 'self'; frame-src 'self'; object-src 'none'; base-uri 'none'; "
               "form-action 'self'; frame-ancestors 'none'")
PERMISSIONS_POLICY = ("accelerometer=(), autoplay=(self), camera=(), display-capture=(), geolocation=(), gyroscope=(), "
                      "hid=(), magnetometer=(), microphone=(), midi=(), payment=(), serial=(), usb=(), xr-spatial-tracking=()")
# Shared, public, cookie-less resources that sandboxed (opaque-origin) apps must be able to load.
SHARED_PREFIXES = ("/apps/", "/sdk/", "/css/", "/assets/")


def allowed_names() -> set[str]:
    names = {"localhost", "pios.local"}
    try:
        h = socket.gethostname().lower()
        names |= {h, h + ".local"}
    except OSError:
        pass
    extra = os.getenv("PIOS_ALLOWED_HOSTS", "")
    names |= {x.strip().lower() for x in extra.split(",") if x.strip()}
    return names


def host_ok(host_header: str, names: set[str]) -> bool:
    h = (host_header or "").strip().lower()
    if not h:
        return False
    if h.startswith("["):                       # [v6]:port
        end = h.find("]")
        host = h[1:end] if end > 0 else ""
    else:
        host = h.rsplit(":", 1)[0] if h.count(":") == 1 else h
    if host in names:
        return True
    try:
        ipaddress.ip_address(host.split("%")[0])    # any IP literal: DNS rebinding needs a name
        return True
    except ValueError:
        return False


async def _plain(send, status: int, text: str, extra=()):
    body = text.encode()
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"text/plain; charset=utf-8"), (b"content-length", str(len(body)).encode()),
                            (b"cache-control", b"no-store"), (b"connection", b"close"), *extra]})
    await send({"type": "http.response.body", "body": body})


class HostGuard:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            host = next((v.decode("latin-1") for k, v in scope["headers"] if k == b"host"), "")
            if not host_ok(host, allowed_names()):
                if scope["type"] == "http":
                    return await _plain(send, 421, "Misdirected Request")
                return await send({"type": "websocket.close", "code": 1008})
        await self.app(scope, receive, send)


def body_limit_for(path: str) -> int:
    if path == "/api/files/upload":
        return config.MAX_UPLOAD + 1024 * 1024        # multipart overhead
    if path.startswith("/api/sdk/"):
        return 12 * 1024 * 1024
    return 2 * 1024 * 1024


class BodyLimit:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] in ("GET", "HEAD", "OPTIONS"):
            return await self.app(scope, receive, send)
        limit = body_limit_for(scope["path"])
        cl = next((v for k, v in scope["headers"] if k == b"content-length"), None)
        if cl is not None:
            try:
                if int(cl) > limit:
                    return await _plain(send, 413, "Request Entity Too Large")
            except ValueError:
                return await _plain(send, 400, "Bad Request")
        state = {"n": 0, "over": False, "started": False}

        async def guarded_receive():
            msg = await receive()
            if msg["type"] == "http.request":
                state["n"] += len(msg.get("body", b""))
                if state["n"] > limit and not state["over"]:
                    state["over"] = True
                    await _plain(send, 413, "Request Entity Too Large")
                    state["started"] = True
                if state["over"]:
                    return {"type": "http.disconnect"}
            return msg

        async def guarded_send(msg):
            if state["over"]:
                return                      # swallow whatever the app emits after we already answered
            await send(msg)

        await self.app(scope, guarded_receive, guarded_send)


class SecureHeaders:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        path = scope["path"]

        async def wrapped(msg):
            if msg["type"] == "http.response.start":
                h = {k.lower(): (k, v) for k, v in msg.get("headers", [])}
                def put(name: bytes, value: bytes, force=False):
                    if force or name not in h:
                        h[name] = (name, value)
                put(b"x-content-type-options", b"nosniff")
                put(b"referrer-policy", b"no-referrer")
                put(b"permissions-policy", PERMISSIONS_POLICY.encode())
                put(b"cross-origin-opener-policy", b"same-origin")
                put(b"cross-origin-resource-policy", b"cross-origin" if path.startswith(SHARED_PREFIXES) else b"same-origin")
                if path.startswith("/apps/"):
                    put(b"x-frame-options", b"SAMEORIGIN")
                else:
                    put(b"x-frame-options", b"DENY")
                    put(b"content-security-policy", DEFAULT_CSP.encode())
                if path.startswith("/api/"):
                    put(b"cache-control", b"no-store", force=True)
                if scope.get("scheme") == "https":
                    put(b"strict-transport-security", b"max-age=31536000")
                msg = {**msg, "headers": list(h.values())}
            await send(msg)

        await self.app(scope, receive, wrapped)
