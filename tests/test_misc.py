def test_notes_crud_and_search(admin):
    nid = admin.post("/api/notes", json={"title": "Einkauf", "body": "Milch 100% bio_"}).json()["id"]
    admin.post("/api/notes", json={"title": "Idee", "body": "Orb"})
    assert len(admin.get("/api/notes").json()) == 2
    assert [n["title"] for n in admin.get("/api/notes", params={"q": "milch"}).json()] == ["Einkauf"]
    assert admin.get("/api/notes", params={"q": "%"}).json()[0]["title"] == "Einkauf"  # wildcard escaped
    assert admin.get("/api/notes", params={"q": "_"}).json()[0]["title"] == "Einkauf"
    assert admin.put(f"/api/notes/{nid}", json={"title": "Neu", "body": "x"}).status_code == 200
    assert admin.put("/api/notes/999", json={"title": "", "body": ""}).status_code == 404
    assert admin.delete(f"/api/notes/{nid}").status_code == 200
    assert len(admin.get("/api/notes").json()) == 1


def test_system(admin):
    s = admin.get("/api/system").json()
    for k in ("cpu", "ram", "disk", "uptime", "net", "version", "temp"):
        assert k in s
    assert 0 <= s["ram"]["percent"] <= 100


def test_prefs_and_desktop_state(admin):
    assert admin.get("/api/prefs").json()["animations"] is True
    assert admin.put("/api/prefs", json={"animations": False, "accent": "violet"}).status_code == 200
    assert admin.get("/api/prefs").json()["accent"] == "violet"
    assert admin.put("/api/prefs", json={"accent": "pink"}).status_code == 422
    state = {"windows": {"files": {"x": 10, "y": 20, "w": 500, "h": 400}}, "open": ["files"]}
    assert admin.put("/api/desktop", json=state).status_code == 200
    assert admin.get("/api/desktop").json() == state
    assert admin.put("/api/desktop", content=b"x" * 70000).status_code == 413


def test_security_headers(client):
    r = client.get("/")
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"
    assert client.get("/healthz").json()["ok"] is True
