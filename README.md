# GNA — Global Network Archive

GNA is a network connection system that uses **meeting places** (relays) to
connect devices running the same program. Once connected, every device can see
the others on the network, browse what they share, download files, search
shared content and users, and interact live — all from a browser-like
dashboard UI.

It also ships with **MedianBox / GNA Tracer**, a full network-intelligence
monitor (packet pipeline, GeoIP map, process/connection tracing, threat
detection, and a tkinter "GNA Tracer" window) that launches alongside the main
program.

---

## Quick Start

```bat
GNA.bat
```

or

```bat
python GNA.py
```

This starts (in roughly this order — the dashboard comes up first, everything
else boots in parallel behind it):

1. The **GNA dashboard** — opens automatically in your browser
   (`http://127.0.0.1:5000`)
2. **MedianBox Monitor + GNA Tracer window** — the complete monitor program in
   its own console (spawned early so its startup overlaps)
3. The **embedded signaling/relay server** — the first running instance hosts
   the meeting place on the first free port of `3000–3003`; later instances
   detect it and connect as clients
4. **Peer discovery** — mDNS (LAN) + the global relay network
5. **sender.py** — screen-share sender (regenerated from inside the monolith
   if missing; in-process fallback if the spawn fails)
6. Your **public IP** — resolved on a background thread so it never delays
   launch

### Standalone monitor

```bat
python Main_monolith.py --medianbox
```

## Ports

| Port        | Service                                          |
|-------------|--------------------------------------------------|
| `5000`      | GNA dashboard / peer HTTP API                    |
| `3000–3003` | Signaling + global relay (embedded, first free)  |
| `8470`      | MedianBox monitor dashboard                      |

## Using GNA

- **Share files** — open *Content Selection* (Explorer), check files/folders,
  add comma-separated tags for search, press **Save Selection**. Shared items
  are served from the shared folder under your `gna://<instance>` address.
- **Find things** — the search bar matches shared files **by name** (every
  word must appear in the filename or its tags) across your own shares and
  every live peer, and users by ID / call number / address. Results show the
  `gna://<instance>/<path>` location and the total files available across all
  shared sources.
- **Preview a peer** — the peer list's preview shows that peer's shared items,
  sizes, and its `gna://` location; every item has a Download button.
- **Download** — files download directly; folders download as a `.zip`.
  Remote items route through `/peer_download/<peer>/<path>` to that peer's
  own `/preview` endpoint.
- **Remote access** — sessions appear in a dashboard banner and can be
  revoked from there or via the relay's REST endpoints.

## Features

- **Peers & devices** — live list of every device on the network with ID,
  call number, address, role (Primary/Backup failover chain) and shared-item
  count. Peer preview modal shows a peer's shared items and its `gna://`
  location.
- **File sharing** — check files/folders in the Explorer to share them, tag
  them for search, preview them, download them (folders download as `.zip`).
- **Network search** — aggregated search of shared files and users across
  the whole network with per-item `gna://` locations and a total-available
  count across all shared sources.
- **Internet tab** — a real in-app browser: multi-engine mass search
  (DuckDuckGo, Bing, Mojeek, Yahoo, AOL, Startpage, Wikipedia, SearX, Brave,
  Qwant, Ecosia, ETools, Mwmbl), 100 results per page, sort/engine-filter/
  page-jump controls, separate Images/Videos/News tabs with their own
  per-tab engine sets, reader-mode page browsing, and an embedded video
  player for YouTube/Vimeo/Twitch/BitChute/Rumble/Streamable/TikTok/
  Bilibili/Odysee/PeerTube plus direct media files.
- **Screen sharing** — `sender.py` streams screen frames to the relay;
  remote access sessions are listed on the dashboard and can be revoked.
- **Vault** — encrypted file vault (X25519 + AES-GCM + HKDF) with optional
  secret-file unlock.
- **Sync** — scheduled folder-sync jobs pull shared files from a peer
  automatically (up to 4 files in parallel per cycle).

## Configuration

`global_config.json` controls the meeting-place network:

```json
{
  "enabled": true,
  "relay_url": "http://localhost:3000",
  "relay_urls": [],
  "network_code": "publan-global-v1",
  "auto_connect": true,
  "brave_api_key": ""
}
```

- `relay_url` / `relay_urls` — your meeting places; the app rotates through
  them and falls back to the embedded relay if none answer.
- `network_code` — only peers on the same code meet.
- `brave_api_key` — optional, enables the Brave search engine.

User data lives in `%LOCALAPPDATA%\Global Network Archive\` (shared paths,
known peers, join time, vault).

## Troubleshooting

- **Slow launch** — always start through `GNA.bat` / `GNA.py`. Running
  `python Main_monolith.py` directly recompiles the whole 3.4 MB file every
  time because `__main__` never uses the `.pyc` cache.
- **`Sender.py: NOT DETECTED`** right after start — the status probe caches
  its result for a few seconds; it updates on the next refresh. If it stays
  down, the in-process embedded sender takes over (`RUNNING (embedded)`).
- **No packet capture in the monitor** — install Npcap; the monitor runs
  without it but packet sniffing is disabled (`winpcap is not installed`
  warning).
- **`Integrity manifest modified` warning** — expected after editing source
  files; it's a verification notice, not a block. Regenerate with
  `generate_manifest()` if the change is intentional.
- **Search engines return few/no results** — some providers block automated
  queries by IP; the fan-out merges whatever subset answers, and results are
  cached for 5 minutes.

## Files

| File                        | Purpose                                             |
|-----------------------------|-----------------------------------------------------|
| `Main_monolith.py`          | The entire application (dashboard + monitor + relay + sender source) |
| `GNA.py` / `GNA.bat`        | Launchers (use the cached `.pyc` — fastest startup) |
| `medianbox_monitor_v2.py`   | Standalone copy of the monitor (launch fallback)    |
| `sender.py`                 | Screen-share sender (regenerated if missing)        |
| `smoke_test.py`             | Route/render smoke test — `python smoke_test.py`    |
| `_jscheck.py`               | Validates embedded `<script>` blocks                |
| `global_config.json`        | Meeting-place / relay configuration                 |
| `.integrity_manifest.json`  | SHA3-256 manifest; startup warns on tampering       |
| `OVERVIEW.md`               | Architecture deep-dive                              |
| `Goal.md`                   | Original project brief                              |
| `ReferenceCode/`            | Legacy reference implementations                    |

## Requirements

Python 3.10+, Windows (primary target). Packages: `flask`, `requests`,
`zeroconf`, `python-socketio`, `uvicorn`, `fastapi`, `Pillow`, `psutil`,
`cryptography`, `mss`, `geoip2`, `manuf`; `scapy` + Npcap for packet capture
(runs degraded without it); `tkinter` for the GNA Tracer window.

## Verification

```bat
python smoke_test.py     REM routes + renders + engines
python _jscheck.py       REM embedded JS blocks
```
