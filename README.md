# Kusylit's Studio

A local-first AI media workbench plugin for **WorkBuddy2API-Hub**.

Kusylit's Studio provides one local page for:

- Text-to-image generation
- Image editing with multiple reference images
- Text-to-video / image-to-video generation
- Async task tracking with progress and cancellation
- Gallery with search, time filters, favorites and deletion
- Prompt tag library with custom categories
- Batch queues with cost confirmation and stop control
- Local console, audit log, balance and gateway health

The plugin is intentionally local: it binds only to `127.0.0.1` and keeps generated media on disk.

## Requirements

- Python 3.10 or newer. No third-party Python packages are required.
- A running [WorkBuddy2API-Hub](https://github.com/ardeyouxipianyi/workbuddy2api-hub) gateway on `http://127.0.0.1:8788`.
- The plugin directory must be a **sibling** of `workbuddy2api-hub`, because the plugin reads the enabled API key from:

```text
../workbuddy2api-hub/accounts/settings.json
```

Directory layout:

```text
your-folder/
├─ workbuddy2api-hub/
└─ kusylit-studio/
   ├─ media_studio.py
   ├─ media-studio.cmd
   └─ ...
```

## Run

### Windows

Double-click `media-studio.cmd`, or run:

```bat
python media_studio.py
```

### Linux / macOS

```sh
./start.sh
# or
python3 media_studio.py
```

Open <http://127.0.0.1:8790/>.

### Stop

- Windows: run `media-studio-stop.cmd`
- Linux / macOS: `Ctrl+C` in the terminal running the server

## Runtime data

The plugin creates these files/directories next to `media_studio.py`:

| Path | Purpose |
|---|---|
| `media-out/` | Generated images and videos |
| `studio-config.json` | Save directory and access-password hash |
| `studio-jobs.json` | Task history |
| `studio-tags.json` | Prompt tag library |
| `studio-favorites.json` | Gallery favorites |
| `studio-console.log` | Persistent console log |
| `studio-audit.log` | Security/action audit log |

They are excluded by `.gitignore` and should not be committed.

`studio-config.example.json` shows the initial configuration shape.

## Security notes

- The HTTP server listens on `127.0.0.1:8790` only.
- `/api/*` requests require a per-process studio token embedded in the page.
- Optional access-password protection uses PBKDF2-SHA256. The password is kept in page memory only, so a refresh asks for it again.
- Generated files are exposed through short-lived HMAC-signed `/files/` URLs.
- Image URLs returned by the upstream gateway are validated: only public `http(s)` hosts are accepted, and private/loopback/link-local targets are rejected.
- Do not put this behind a public reverse proxy without adding TLS, authentication and network-level rate limiting.

## Notes

This is an independent companion UI. WorkBuddy and WorkBuddy2API-Hub belong to their respective authors; this repository is not an official WorkBuddy client.

Author: **Kusylit**
