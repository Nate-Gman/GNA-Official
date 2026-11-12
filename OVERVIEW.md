# GNA Architecture Overview

`Main_monolith.py` is the entire system in one file (~65k lines): the GNA
peer application, the embedded signaling/relay server, the screen-share
sender source, and the complete MedianBox/GNA Tracer monitor.

## Process layout

```
GNA.bat ──► GNA.py ──► import Main_monolith ──► main()
                                              ├─ Flask dashboard    :5000   (thread)
                                              ├─ MedianBox monitor  (new console process)
                                              │    ├─ monitor threads (packet pipeline, GeoIP, RF, …)
                                              │    ├─ FastAPI dashboard :8470
                                              │    └─ GNATracerGUI (tkinter, 16 tabs)
                                              ├─ PublicIP           (thread — external lookup)
                                              └─ ServiceBootstrap   (thread)
                                                   ├─ Zeroconf register + ServiceBrowser (mDNS LAN)
                                                   ├─ _GNARelay (socket.io ASGI + uvicorn) :3000-3003
                                                   ├─ GlobalDiscoveryService (socket.io client)
                                                   ├─ server.js check/spawn (if present)
                                                   ├─ sender.py spawn → _embedded_sender_main fallback
                                                   └─ caller.py spawn (if present)
```

## Threads

| Thread                | Role                                                        |
|-----------------------|-------------------------------------------------------------|
| `ImportPrewarm:*`     | One per dependency group — parallel heavy imports at module load |
| `FlaskThread`         | `app.run(0.0.0.0:5000)` — the whole HTTP/API surface          |
| `ServiceBootstrap`    | All network services in dependency order                      |
| `PublicIP`            | `get_public_ip()` → fills `state.public_ip`                   |
| `DiscoveryThread`     | Peer bookkeeping, stale-peer refresh, periodic peer exchange  |
| `StatusThread`        | `print_live_status` every interval (2s initial delay)         |
| `GNARelay:<port>`     | uvicorn `server.run` for the embedded ASGI relay              |
| `GlobalDiscoveryThread` | asyncio loop: connect/register/heartbeat to relay          |
| `EmbeddedSender`      | In-process screen-share fallback                              |
| `SenderProbe`/`SignalingProbe` | One-shot status re-probes behind the status cache     |

## Launch path (performance design)

Startup is ordered so the dashboard is reachable in ~3.5s instead of ~10s+:

- **Critical path**: integrity check → ids/paths → `Flask()` → `create_routes`
  → Flask thread → `_wait_port_open` → MedianBox spawn → `webbrowser.open`.
- **Off path**: public-IP lookup (up to 5s HTTP), zeroconf registration
  (~2s announce), relay, global discovery, server.js, sender, caller — all on
  background threads.
- `_BOOT_REFS` pins Zeroconf/ServiceBrowser/Popen objects created on the
  bootstrap thread (the old code relied on `main()`'s immortal frame).
- Note: `python Main_monolith.py` directly recompiles the whole file every
  launch (`__main__` never uses `.pyc`) — launch via `GNA.py`/`GNA.bat`.

## Parallel import pre-warm

`flask` (~1.9s), `socketio`, `fastapi`, `uvicorn`, `PIL`, `tkinter`,
`asyncio` cost ~3-4s combined and are referenced only inside function bodies.
Each group imports on its own daemon thread at module start (import I/O
releases the GIL), then injects the real names into module globals so plain
`Flask(...)`, `jsonify(...)`, `tk.Tk()` lookups work unchanged.

| Group      | Injects                                                        | `_require()` gate at |
|------------|----------------------------------------------------------------|----------------------|
| `flask`    | `Flask`, `Response`, `flask_request`, `jsonify`, `abort`, `redirect`, `send_from_directory`, `stream_with_context` | `main`, `create_routes` |
| `socketio` | `socketio`                                                     | `_bootstrap_network_services`, `_start_embedded_relay`, `_embedded_sender_main`, `GlobalDiscoveryService.start`, `medianbox_main` |
| `fastapi`  | `FastAPI`, `WebSocket*`, `HTMLResponse`, `JSONResponse`, `uvicorn` | `start_dashboard`, `medianbox_main` |
| `pil`      | `Image`, `ImageTk`                                             | `_run_gui`, `TileManager.*`, `medianbox_main` |
| `tkinter`  | `tk`, `ttk`, `scrolledtext`, `messagebox`                      | `_run_gui`, `medianbox_main` |
| `asyncio`  | `asyncio`                                                      | `GlobalDiscoveryService.start`, `start_dashboard`, `medianbox_main` |

`HAS_SOCKETIO`/`HAS_FASTAPI`/`HAS_PIL`/`HAS_TKINTER` are set from
`importlib.util.find_spec` instead of a trial import. Zeroconf and `requests`
stay eager (`PeerDiscoveryListener(ServiceListener)` class base and the
module-level `_HTTP_SESSION` need them at exec time).

## Meeting places (connection model)

- **Embedded relay** (`_GNARelay`): `socketio.AsyncServer(async_mode='asgi')`
  served by uvicorn. The first instance to run binds the first free port of
  `3000–3003` and *hosts the meeting place*; other instances detect `/health`
  already answering and join as clients. Events: `register-global-peer`,
  `global-peer-list`, `request-global-peers`, `share-updated`,
  `remote-access-register`, `remote-access-status`, `screen-frame`,
  `remote-input`; REST: `/health`, `/api/remote-access-status`,
  `/api/remote-access-revoke`.
- **GlobalDiscoveryService**: socket.io client that rotates through
  `relay_urls` (config) → `GNA_RELAY_URLS` env → the eight default meeting
  places (3000–3003, localhost + 127.0.0.1). Registers every ~5s heartbeat;
  keeps `_global_call_numbers` and the live peer roster.
- **LAN**: zeroconf `_databank._tcp.local.` service registration + browser.
- **Status probes**: `check_sender_status` / `check_signaling_server_status`
  return a cached value and re-probe on a background thread
  (`_STATUS_CACHE_TTL`) so health checks never block an HTTP request.

## Shared files & search

- `/shared_list` + `/shared_count` are the peer-facing APIs every node serves.
- `search_network()` fans out `fetch_peer_shared_list(ip, port)` to all live
  peers on `_WEB_POOL`, merges with local `shared_paths`, matches each query
  word against name + tags, and returns `(results, total_available)`.
- `search_users()` matches ID / call number / `ip:port`.
- `SearchResult.location` = `gna://<instance_id>/<path>` — rendered as the
  location next to self and peer files everywhere (search results, peer
  preview, own `/preview` page, users table).
- Downloads: local → `/preview/<path>?download=1` (file or folder zip);
  remote → `/peer_download/<peer>/<path>` → 302 to
  `http://<peer_ip>:<port>/preview/<path>?download=1`.
- `is_path_safe` guards traversal; `list_directory_entries` bounds explorer
  reads to `SHARED_DIR`.
- Sync worker (`run_sync_job`) pulls a peer's shared files into a local
  folder, up to 4 downloads in parallel per cycle.

## Key routes

| Route                                   | Purpose                                  |
|-----------------------------------------|------------------------------------------|
| `/`, `/dashboard`, `/start`, `/internet`, `/settings` | Browser-shell pages         |
| `/explorer`, `/save_selection`          | Pick/tag shared content                  |
| `/preview/<path>`                       | Local shared listing/download            |
| `/my_preview`, `/peer_preview/<id>`     | Shared-items modal (self / peer)         |
| `/peer_download/<peer>/<path>`          | Remote-download redirect                 |
| `/peer_connect/<id>`                    | Open a peer's dashboard                  |
| `/shared_list`, `/shared_count`         | Peer-facing file APIs                    |
| `/search?q=`                            | Aggregated file+user search page         |
| `/api/peers`, `/api/info`, `/api/search-users` | Peer/state JSON                   |
| `/api/web-search`, `/api/media-search`  | Internet search backends                 |
| `/browse`, `/api/fetch`                 | Reader-mode proxy + fetch proxy (≤200MB) |
| `/api/settings-status`, `/api/global-status`, `/api/global-config`, `/api/global-reconnect` | Status/config |
| `/vault*`                               | Encrypted vault pages/actions            |
| `/health`, `/api/remote-access-*`       | On the relay (3000-3003), not :5000      |

## Internet tab

- `/api/web-search` → `mass_web_search()`: every engine runs on `_WEB_POOL`
  (96 workers) with a 9s deadline; engines that support pagination fan out
  multiple pages concurrently via `_run_fanout`. Results are merged/deduped
  per-URL, engine-attributed, capped at 1000, and cached 5 min.
- `/api/media-search` → `mass_media_search()`: per-medium source sets
  (images: bing/openverse/commons/ddg; videos: bing/ddg; news: bing RSS/gdelt/
  ddg) with the `engine=` filter honored per tab.
- `/browse` → `rewrite_for_browse()` sanitizes pages into reader mode.
  `_video_embed_for()` detects playable providers/direct media first and
  routes to `_video_player_page` (iframe embeds, `<video>` via `/api/fetch`,
  hls.js for `.m3u8`) before sanitization can strip players.
- `_HTTP_SESSION`: pooled `requests.Session` (64 conns / 128 max per scheme).
- An `after_request` middleware gzips text responses ≥1KB when the client
  accepts it (the ~140–190KB shell/dashboard compress ~8×).

## Screen sharing & remote access

- `sender.py` is embedded as `_SENDER_SRC`; `_ensure_sender_script()` rewrites
  it at launch if missing. It streams JPEG frames (`mss`+PIL, ~2fps) as
  `screen-frame` events to the first healthy relay port.
- Backup route: `_embedded_sender_main()` runs the same loop in-process;
  `_probe_sender_status()` reports `RUNNING (embedded)` (Method 0), then
  `_sender_pid`/`pid_exists` (1), a `sender.py` cmdline scan (2), and a
  window-title check (3).
- Remote-access sessions are registered on the relay; the dashboard banner +
  revoke button hit the relay's REST endpoints via `_relay_origin()`.

## Data files & vault

- `DATA_DIR` = `%LOCALAPPDATA%\Global Network Archive\`: `shared_paths.json`,
  `known_peers.json`, `my_join_time.txt`, vault. `migrate_legacy_files()`
  copies old names forward on first run.
- `sender_session_id.txt` in the project dir identifies the sender session to
  the relay.
- Vault: `SecureVault` uses X25519 + AES-GCM + HKDF (`cryptography`), optional
  secret-file gate; files are listed/opened/removed via `/vault*` routes.

## Integrity & tests

- `generate_manifest`/`verify_integrity` hash all source files with
  SHA3-256 into `.integrity_manifest.json`; `run_startup_integrity_check`
  warns on drift but never blocks.
- `smoke_test.py` exercises every render function and GET/POST route through
  a Flask test client. `_jscheck.py` extracts every `<script>` block from the
  source and syntax-checks it (catches quote-escaping bugs in templates).
