import hashlib, os, secrets, sqlite3, time
from pathlib import Path
import psutil
from argon2 import PasswordHasher
from fastapi import FastAPI, Depends, File, HTTPException, Request, Response, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT=Path(__file__).resolve().parent.parent
DATA=Path(os.getenv("PIOS_DATA", ROOT/"data")).resolve()
DATA.mkdir(parents=True,exist_ok=True)
DB=DATA/"pios.db"
ph=PasswordHasher()
app=FastAPI(title="PiOS NOVA",docs_url=None,redoc_url=None)
def conn():
 c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c
with conn() as db:
 db.execute("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)")
 db.execute("CREATE TABLE IF NOT EXISTS sessions(hash TEXT PRIMARY KEY, uid INTEGER, expires INTEGER)")
 db.execute("CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY, uid INTEGER, title TEXT, body TEXT, updated INTEGER)")
class Credentials(BaseModel):
 username:str=Field(min_length=3,max_length=40)
 password:str=Field(min_length=12,max_length=256)
class Note(BaseModel):
 title:str=Field(max_length=150)
 body:str=Field(max_length=100000)
def user(request:Request):
 token=request.cookies.get("pios_session","")
 with conn() as db:
  r=db.execute("SELECT users.id,users.username FROM sessions JOIN users ON users.id=sessions.uid WHERE hash=? AND expires>?",(hashlib.sha256(token.encode()).hexdigest(),int(time.time()))).fetchone()
 if not r: raise HTTPException(401,"Bitte anmelden")
 return dict(r)
@app.middleware("http")
async def headers(request:Request,call_next):
 if request.method in ("POST","PUT","PATCH","DELETE") and request.headers.get("origin") not in (None,str(request.base_url).rstrip("/")):
  from fastapi.responses import JSONResponse
  return JSONResponse({"detail":"Origin nicht erlaubt"},status_code=403)
 response=await call_next(request)
 response.headers["X-Content-Type-Options"]="nosniff"
 response.headers["X-Frame-Options"]="DENY"
 response.headers["Content-Security-Policy"]="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
 return response
@app.get("/api/setup-status")
def status():
 with conn() as db: n=db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
 return {"needs_setup":not bool(n)}
@app.post("/api/setup")
def setup(c:Credentials):
 with conn() as db:
  db.execute("BEGIN IMMEDIATE")
  if db.execute("SELECT COUNT(*) FROM users").fetchone()[0]: raise HTTPException(409,"Bereits eingerichtet")
  db.execute("INSERT INTO users(username,password) VALUES(?,?)",(c.username,ph.hash(c.password)))
 return {"ok":True}
@app.post("/api/login")
def login(c:Credentials,response:Response,request:Request):
 with conn() as db:
  r=db.execute("SELECT * FROM users WHERE username=?",(c.username,)).fetchone()
  try: valid=bool(r and ph.verify(r["password"],c.password))
  except Exception: valid=False
  if not valid: raise HTTPException(401,"Anmeldung fehlgeschlagen")
  token=secrets.token_urlsafe(48)
  db.execute("INSERT INTO sessions VALUES(?,?,?)",(hashlib.sha256(token.encode()).hexdigest(),r["id"],int(time.time())+86400))
 response.set_cookie("pios_session",token,httponly=True,samesite="strict",secure=request.url.scheme=="https",max_age=86400)
 return {"ok":True}
@app.get("/api/me")
def me(u=Depends(user)):return u
@app.post("/api/logout")
def logout(request:Request,response:Response,u=Depends(user)):
 with conn() as db: db.execute("DELETE FROM sessions WHERE hash=?",(hashlib.sha256(request.cookies.get("pios_session","").encode()).hexdigest(),))
 response.delete_cookie("pios_session")
 return {"ok":True}
@app.get("/api/apps")
def apps(u=Depends(user)):
 return [{"id":x,"name":y} for x,y in [("files","NOVA Files"),("notes","NOVA Notes"),("monitor","NOVA Monitor"),("settings","NOVA Settings")]]
@app.get("/api/system")
def system(u=Depends(user)):
 mem=psutil.virtual_memory(); disk=psutil.disk_usage(str(DATA)); temps=psutil.sensors_temperatures()
 temp=next((round(v.current,1) for values in temps.values() for v in values),None)
 return {"cpu":psutil.cpu_percent(interval=.1),"ram":mem.percent,"disk":disk.percent,"temp":temp,"uptime":int(time.time()-psutil.boot_time())}
@app.get("/api/notes")
def notes(u=Depends(user)):
 with conn() as db:return [dict(x) for x in db.execute("SELECT id,title,body,updated FROM notes WHERE uid=? ORDER BY updated DESC",(u["id"],))]
@app.post("/api/notes")
def save_note(n:Note,u=Depends(user)):
 with conn() as db:
  c=db.execute("INSERT INTO notes(uid,title,body,updated) VALUES(?,?,?,?)",(u["id"],n.title,n.body,int(time.time())))
  return {"id":c.lastrowid}
@app.put("/api/notes/{ident}")
def edit_note(ident:int,n:Note,u=Depends(user)):
 with conn() as db:
  c=db.execute("UPDATE notes SET title=?,body=?,updated=? WHERE id=? AND uid=?",(n.title,n.body,int(time.time()),ident,u["id"]))
  if not c.rowcount:raise HTTPException(404)
 return {"ok":True}
@app.delete("/api/notes/{ident}")
def delete_note(ident:int,u=Depends(user)):
 with conn() as db:db.execute("DELETE FROM notes WHERE id=? AND uid=?",(ident,u["id"]))
 return {"ok":True}
def directory(u):
 p=(DATA/"files"/str(u["id"]));p.mkdir(parents=True,exist_ok=True);return p
def target(u,name):
 if name in ("",".","..") or Path(name).name!=name:raise HTTPException(400,"Ungültiger Name")
 return directory(u)/name
@app.get("/api/files")
def files(u=Depends(user)):
 return [{"name":p.name,"size":p.stat().st_size} for p in directory(u).iterdir() if p.is_file()]
@app.post("/api/files")
async def upload(file:UploadFile=File(...),u=Depends(user)):
 p=target(u,file.filename or "")
 if p.exists():raise HTTPException(409,"Datei existiert")
 count=0
 with p.open("xb") as f:
  try:
   while data:=await file.read(65536):
    count+=len(data)
    if count>25*1024*1024:raise HTTPException(413,"Maximal 25 MB")
    f.write(data)
  except Exception:
   p.unlink(missing_ok=True);raise
 return {"name":p.name,"size":count}
@app.get("/api/files/{name}")
def download(name:str,u=Depends(user)):
 p=target(u,name)
 if not p.is_file():raise HTTPException(404)
 return FileResponse(p,filename=p.name,media_type="application/octet-stream")
@app.delete("/api/files/{name}")
def delete(name:str,u=Depends(user)):
 p=target(u,name)
 if not p.is_file():raise HTTPException(404)
 p.unlink();return {"ok":True}
app.mount("/static",StaticFiles(directory=ROOT/"web"),name="static")
@app.get("/")
def index():return FileResponse(ROOT/"web"/"index.html")
