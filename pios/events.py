"""PiOS Events: a small in-process notification/event log, polled by the shell."""
import threading
import time
from collections import deque

from fastapi import APIRouter, Depends, Query

from .security import current_user

router = APIRouter(prefix="/api")
_lock = threading.Lock()
_log: deque = deque(maxlen=200)
_seq = 0


def publish(uid: int, kind: str, **data) -> int:
    global _seq
    with _lock:
        _seq += 1
        _log.append({"id": _seq, "uid": uid, "kind": kind, "time": int(time.time()), **data})
        return _seq


@router.get("/events")
def events(since: int = Query(0, ge=0), u=Depends(current_user)):
    with _lock:
        items = [{k: v for k, v in e.items() if k != "uid"} for e in _log if e["id"] > since and e["uid"] == u["id"]]
        return {"last": _seq, "events": items}
