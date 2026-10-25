"""PiOS NOVA application entry point: `uvicorn pios.main:app`."""
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from . import __version__, apps, auth, config, db, events, files, notes, prefs, security, system

CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; "
       "media-src 'self'; connect-src 'self'; frame-src 'self'; object-src 'none'; base-uri 'none'; "
       "form-action 'self'; frame-ancestors 'none'")


@asynccontextmanager
async def lifespan(_app):
    db.init()
    auth.ensure_setup_code()
    apps.registry.reload()
    yield


app = FastAPI(title="PiOS NOVA", version=__version__, docs_url=None, redoc_url=None, openapi_url=None,
              lifespan=lifespan, dependencies=[Depends(security.csrf_guard)])
for module in (auth, system, prefs, notes, files, events, apps):
    app.include_router(module.router)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    h = response.headers
    h.setdefault("X-Content-Type-Options", "nosniff")
    h.setdefault("Referrer-Policy", "no-referrer")
    if request.url.path.startswith("/apps/"):
        h.setdefault("X-Frame-Options", "SAMEORIGIN")
    else:
        h.setdefault("X-Frame-Options", "DENY")
        h.setdefault("Content-Security-Policy", CSP)
    if request.url.path.startswith("/api/"):
        h["Cache-Control"] = "no-store"
    return response


@app.get("/healthz", include_in_schema=False)
def healthz():
    return JSONResponse({"ok": True, "version": __version__})


app.mount("/", StaticFiles(directory=config.WEB, html=True), name="web")
