"""NOVA Notes storage."""
import time

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from . import db
from .security import current_user

router = APIRouter(prefix="/api/notes")


class Note(BaseModel):
    title: str = Field(default="", max_length=150)
    body: str = Field(default="", max_length=200_000)


@router.get("")
def list_notes(q: str = Query("", max_length=100), u=Depends(current_user)):
    sql, args = "SELECT id,title,body,updated FROM notes WHERE uid=?", [u["id"]]
    if q.strip():
        like = "%" + q.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        sql += " AND (title LIKE ? ESCAPE '\\' OR body LIKE ? ESCAPE '\\')"
        args += [like, like]
    with db.connect() as c:
        return [dict(r) for r in c.execute(sql + " ORDER BY updated DESC LIMIT 1000", args)]


@router.post("")
def create(n: Note, u=Depends(current_user)):
    with db.connect() as c:
        cur = c.execute("INSERT INTO notes(uid,title,body,updated) VALUES(?,?,?,?)",
                        (u["id"], n.title, n.body, int(time.time())))
    return {"id": cur.lastrowid}


@router.put("/{note_id}")
def update(note_id: int, n: Note, u=Depends(current_user)):
    with db.connect() as c:
        cur = c.execute("UPDATE notes SET title=?,body=?,updated=? WHERE id=? AND uid=?",
                        (n.title, n.body, int(time.time()), note_id, u["id"]))
    if not cur.rowcount:
        raise HTTPException(404, "Notiz nicht gefunden")
    return {"ok": True}


@router.delete("/{note_id}")
def delete(note_id: int, u=Depends(current_user)):
    with db.connect() as c:
        c.execute("DELETE FROM notes WHERE id=? AND uid=?", (note_id, u["id"]))
    return {"ok": True}
