import pytest


def up(c, name, data=b"hello", path=""):
    return c.post("/api/files/upload", params={"path": path}, files={"file": (name, data)})


def test_upload_list_download_delete(admin):
    assert up(admin, "a.txt").status_code == 200
    assert up(admin, "a.txt").status_code == 409
    e = admin.get("/api/files").json()["entries"]
    assert e[0]["name"] == "a.txt" and e[0]["size"] == 5
    r = admin.get("/api/files/download", params={"path": "a.txt"})
    assert r.content == b"hello" and "attachment" in r.headers["content-disposition"]
    assert admin.delete("/api/files", params={"path": "a.txt"}).status_code == 200
    assert admin.get("/api/files").json()["entries"] == []


def test_folders_rename_move(admin):
    assert admin.post("/api/files/mkdir", json={"path": "", "name": "docs"}).status_code == 200
    assert admin.post("/api/files/mkdir", json={"path": "", "name": "docs"}).status_code == 409
    up(admin, "a.txt")
    assert admin.post("/api/files/rename", json={"path": "a.txt", "new_name": "b.txt"}).status_code == 200
    assert admin.post("/api/files/move", json={"path": "b.txt", "dest": "docs"}).status_code == 200
    assert [x["name"] for x in admin.get("/api/files", params={"path": "docs"}).json()["entries"]] == ["b.txt"]
    # moving a folder into itself is refused
    assert admin.post("/api/files/mkdir", json={"path": "docs", "name": "sub"}).status_code == 200
    assert admin.post("/api/files/move", json={"path": "docs", "dest": "docs/sub"}).status_code == 400
    assert admin.delete("/api/files", params={"path": "docs"}).status_code == 200


@pytest.mark.parametrize("bad", ["../x", "..", "a/b", "a\\b", "", ".", "x\x00y", "x" * 300])
def test_invalid_names(admin, bad):
    assert admin.post("/api/files/mkdir", json={"path": "", "name": bad}).status_code in (400, 422)


@pytest.mark.parametrize("path", ["../../etc/passwd", "/etc/passwd", "..%2f..%2fetc/passwd", "a/../../x"])
def test_path_traversal_blocked(admin, path):
    for url in ("/api/files", "/api/files/download"):
        r = admin.get(url, params={"path": path})
        assert r.status_code in (400, 404), (url, path, r.status_code)
    assert admin.delete("/api/files", params={"path": path}).status_code in (400, 404)


def test_symlink_not_followed(admin):
    from pios import vfs
    root = vfs.user_root(1)
    (root / "evil").symlink_to("/etc")
    assert admin.get("/api/files", params={"path": "evil"}).status_code == 400
    assert all(e["name"] != "evil" for e in admin.get("/api/files").json()["entries"])


def test_inline_only_for_safe_types(admin):
    up(admin, "p.png", b"\x89PNG")
    up(admin, "x.html", b"<script>alert(1)</script>")
    up(admin, "x.svg", b"<svg onload=alert(1)/>")
    r = admin.get("/api/files/download", params={"path": "p.png", "inline": "true"})
    assert r.headers["content-type"] == "image/png" and "inline" in r.headers["content-disposition"]
    for n in ("x.html", "x.svg"):
        r = admin.get("/api/files/download", params={"path": n, "inline": "true"})
        assert "attachment" in r.headers["content-disposition"]
        assert r.headers["content-type"] == "application/octet-stream"
    assert "sandbox" in r.headers["content-security-policy"]


def test_upload_limit(admin, monkeypatch):
    from pios import config
    monkeypatch.setattr(config, "MAX_UPLOAD", 10)
    assert up(admin, "big.bin", b"x" * 100).status_code == 413
    assert admin.get("/api/files").json()["entries"] == []


def test_usage(admin):
    up(admin, "a.txt", b"12345")
    u = admin.get("/api/files/usage").json()
    assert u["used"] == 5 and u["disk_total"] > 0
