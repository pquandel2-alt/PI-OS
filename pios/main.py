"""PiOS NOVA application entry point: `uvicorn pios.main:app`."""
import asyncio
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from . import DB_SCHEMA, __version__, apps, auth, config, db, events, files, notes, prefs, security, system, updates, hardening, shield


@asynccontextmanager
async def lifespan(_app):
    db.init()
    auth.ensure_setup_code()
    apps.registry.reload()
    apps.sync_app_state()
    tasks = [asyncio.create_task(updates.notify_loop()), asyncio.create_task(shield.malware_loop())]
    try:
        yield
    finally:
        for t in tasks:
            t.cancel()


app = FastAPI(title="PiOS NOVA", version=__version__, docs_url=None, redoc_url=None, openapi_url=None,
              lifespan=lifespan, dependencies=[Depends(security.csrf_guard)])
for module in (auth, system, prefs, notes, files, events, apps, updates, shield):
    app.include_router(module.router)


@app.get("/healthz", include_in_schema=False)
def healthz():
    checks = {"db": db.healthy(), "apps": all(a in apps.registry.apps for a in ("files", "notes", "monitor", "settings", "updates"))}
    return JSONResponse({"ok": all(checks.values()), "version": __version__, "schema": DB_SCHEMA, "checks": checks})


# add_middleware wraps: the last one added is outermost. Order of processing: SecureHeaders (decorates every answer,
# including 421/413) -> HostGuard -> BodyLimit -> application.
app.add_middleware(hardening.BodyLimit)
app.add_middleware(hardening.HostGuard)
app.add_middleware(hardening.SecureHeaders)
app.mount("/", StaticFiles(directory=config.WEB, html=True), name="web")
