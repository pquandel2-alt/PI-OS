"""PiOS NOVA application entry point: `uvicorn pios.main:app`."""
import asyncio
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from . import DB_SCHEMA, __version__, apps, auth, config, db, events, files, notes, prefs, security, system, updates, hardening, shield, connectivity


@asynccontextmanager
async def lifespan(_app):
    db.init()
    auth.ensure_setup_code()
    apps.registry.reload()
    apps.sync_app_state()
    tasks = [asyncio.create_task(updates.notify_loop()), asyncio.create_task(shield.malware_loop()), asyncio.create_task(connectivity.events_loop())]
    try:
        yield
    finally:
        for t in tasks:
            t.cancel()


app = FastAPI(title="PiOS NOVA", version=__version__, docs_url=None, redoc_url=None, openapi_url=None,
              lifespan=lifespan, dependencies=[Depends(security.csrf_guard)])
for module in (auth, system, prefs, notes, files, events, apps, updates, shield, connectivity):
    app.include_router(module.router)


@app.exception_handler(RequestValidationError)
async def validation_error(_request, exc: RequestValidationError):
    """Never echo submitted values back (they may be Wi-Fi passwords or tokens): location, message and type only."""
    return JSONResponse({"detail": [{"loc": e.get("loc"), "msg": e.get("msg"), "type": e.get("type")} for e in exc.errors()]}, status_code=422)


@app.get("/healthz", include_in_schema=False)
def healthz():
    checks = {"db": db.healthy(), "apps": all(a in apps.registry.apps for a in ("files", "notes", "monitor", "settings", "updates", "shield", "network"))}
    return JSONResponse({"ok": all(checks.values()), "version": __version__, "schema": DB_SCHEMA, "checks": checks})


# add_middleware wraps: the last one added is outermost. Order of processing: SecureHeaders (decorates every answer,
# including 421/413) -> HostGuard -> BodyLimit -> application.
app.add_middleware(hardening.BodyLimit)
app.add_middleware(hardening.HostGuard)
app.add_middleware(hardening.SecureHeaders)
app.mount("/", StaticFiles(directory=config.WEB, html=True), name="web")
