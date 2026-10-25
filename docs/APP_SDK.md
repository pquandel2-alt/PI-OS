# PiOS App SDK (API version 1)

An app is a folder in `/opt/pios/apps/<id>/` (development: `apps/<id>/`) with a `manifest.json` and static web files.

```json
{
  "id": "hello",              // [a-z0-9.-], 2-48 chars, must equal the folder name
  "name": "Hello NOVA",
  "version": "0.1.0",         // semver
  "api": 1,                   // required SDK API version (refused when newer than the server's)
  "entry": "index.html",
  "icon": "spark",            // one of the NOVA icon names
  "permissions": ["storage", "notifications", "system.read"],
  "window": { "width": 420, "height": 360 }
}
```

## Runtime

The shell opens the app in `<iframe sandbox="allow-scripts">` served from `/apps/<id>/` with
`Content-Security-Policy: sandbox allow-scripts; default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'none'`.
The app has no network access, no cookies and no access to the shell. Include the SDK and the shared design system:

```html
<link rel="stylesheet" href="/sdk/pios-ui.css">   <!-- NOVA tokens + components (.btn, .panel, .input, ...) -->
<script src="/sdk/pios-sdk.js"></script>
```

## `pios.*`

| API | Permission | Notes |
|---|---|---|
| `pios.ready` | – | resolves `{app, version, api, permissions, accent}` |
| `pios.window.setTitle/close/minimize/toggleMaximize` | – | |
| `pios.ui.toast(title, body, level)`, `pios.ui.onTheme(fn)` | – | |
| `pios.storage.get/set/remove(key[, value])` | `storage` | JSON values, 256 KB per value, 4 MB per app and user |
| `pios.files.list/read/readText/write(path)` | `files.app` (folder `Apps/<id>/` only), `files.read`, `files.write` (whole user tree) | 10 MB per call |
| `pios.system.info()` | `system.read` | cpu, ram, disk, temp, uptime |
| `pios.notifications.show(title, body, level)` | `notifications` | appears in the shell tray |
| `pios.events.emit(topic, data)` / `on(topic, fn)` | – | emit only in the namespace `"<appId>.*"` |

Calls are `postMessage` requests to the shell. For anything that touches data the shell forwards to `/api/sdk/*` with a
signed token; **the server checks the token's permissions**, so a modified shell/iframe cannot exceed the manifest.

## Lifecycle and updates

`GET /api/apps` lists registered apps; invalid manifests are skipped and reported (`errors`), never fatal. An app is
updated by replacing its folder (higher `version`) and calling `Registry.reload()` (restart of `pios.service` in 0.1).
Because apps hold no backend code, a faulty app can only break its own window.

## Out of scope for 0.1

Installing apps from an app store, per-install permission prompts, apps with server-side components (these will need
per-app OS users/containers and resource quotas), app signing.

See `apps/hello/` for a complete example.
