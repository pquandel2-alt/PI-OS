"""Release sources. GitHubSource uses the official GitHub Releases REST API (public repos, no token)."""
import http.client
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

USER_AGENT = "PiOS-NOVA-Updater/1"
ALLOWED_HOSTS = ("api.github.com", "github.com", "objects.githubusercontent.com",
                 "release-assets.githubusercontent.com", "github-releases.githubusercontent.com")


class SourceError(Exception):
    def __init__(self, msg, retry_after=None):
        super().__init__(msg)
        self.retry_after = retry_after


class Cancelled(Exception):
    pass


@dataclass
class Asset:
    name: str
    url: str
    size: int


@dataclass
class Release:
    tag: str
    prerelease: bool
    published: str
    assets: dict = field(default_factory=dict)  # name -> Asset


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, allow_insecure):
        self.allow_insecure = allow_insecure

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _check_url(newurl, self.allow_insecure)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _check_url(url, allow_insecure):
    u = urllib.parse.urlparse(url)
    if allow_insecure:
        return
    if u.scheme != "https" or u.hostname not in ALLOWED_HOSTS:
        raise SourceError(f"Unerlaubtes Download-Ziel: {u.scheme}://{u.hostname}")


class GitHubSource:
    def __init__(self, repo="pquandel2-alt/PI-OS", api_base="https://api.github.com", allow_insecure=False, timeout=20):
        self.repo, self.api_base, self.allow_insecure, self.timeout = repo, api_base.rstrip("/"), allow_insecure, timeout
        self.opener = urllib.request.build_opener(_SafeRedirect(allow_insecure))

    def _open(self, url, headers=None):
        _check_url(url, self.allow_insecure)
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
        try:
            return self.opener.open(req, timeout=self.timeout)
        except urllib.error.HTTPError as e:
            if e.code == 304:
                raise
            if e.code in (403, 429):
                reset = e.headers.get("x-ratelimit-reset")
                ra = e.headers.get("retry-after")
                wait = int(ra) if ra and ra.isdigit() else None
                if reset and reset.isdigit():
                    import time
                    wait = max(60, int(reset) - int(time.time()))
                raise SourceError("GitHub-Anfragelimit erreicht", retry_after=wait or 3600) from None
            raise SourceError(f"GitHub antwortete mit HTTP {e.code}") from None
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise SourceError(f"Keine Verbindung zu GitHub ({getattr(e, 'reason', e)})") from None

    def list_releases(self, etag=None, limit=20):
        """Returns (releases | None if unchanged, etag)."""
        h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if etag:
            h["If-None-Match"] = etag
        try:
            r = self._open(f"{self.api_base}/repos/{self.repo}/releases?per_page={limit}", h)
        except urllib.error.HTTPError:
            return None, etag
        with r:
            try:
                data = json.loads(r.read(5_000_000))
            except ValueError:
                raise SourceError("Ungültige Antwort der GitHub-API") from None
            new_etag = r.headers.get("ETag", etag)
        out = []
        for d in data if isinstance(data, list) else []:
            if d.get("draft"):
                continue
            assets = {a["name"]: Asset(a["name"], a["browser_download_url"], int(a.get("size", 0)))
                      for a in d.get("assets", []) if a.get("state", "uploaded") == "uploaded"}
            out.append(Release(d.get("tag_name", ""), bool(d.get("prerelease")), d.get("published_at") or "", assets))
        return out, new_etag

    def fetch_small(self, url, max_bytes=2_000_000) -> bytes:
        try:
            with self._open(url) as r:
                data = r.read(max_bytes + 1)
        except (OSError, http.client.HTTPException) as e:
            raise SourceError(f"Download unterbrochen ({e})") from None
        if len(data) > max_bytes:
            raise SourceError("Datei unerwartet groß")
        return data

    def download(self, url, dest, expected_size, progress=None, cancel=None):
        """Resumable download into `dest` (a .part file). Returns when `expected_size` bytes are present."""
        have = os.path.getsize(dest) if os.path.exists(dest) else 0
        if have > expected_size:
            os.remove(dest); have = 0
        while have < expected_size:
            headers = {"Range": f"bytes={have}-"} if have else {}
            r = self._open(url, headers)
            with r:
                if have and r.status != 206:      # server ignored Range: start over
                    have = 0
                mode = "ab" if have else "wb"
                with open(dest, mode) as f:
                    got_any = False
                    try:
                        while True:
                            if cancel and cancel():
                                raise Cancelled()
                            chunk = r.read(256 * 1024)
                            if not chunk:
                                break
                            got_any = True
                            f.write(chunk); have += len(chunk)
                            if have > expected_size:
                                raise SourceError("Download größer als erwartet")
                            if progress:
                                progress(have / expected_size)
                    except (OSError, urllib.error.URLError, http.client.HTTPException) as e:
                        if not got_any:
                            raise SourceError(f"Download unterbrochen ({e})") from None
                        # partial progress kept; loop re-requests the remainder
            if have < expected_size and not got_any:
                raise SourceError("Download unterbrochen")
        return have
