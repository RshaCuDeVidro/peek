# peek

**Async RTSP camera scanner** — reconnaissance, fingerprinting, ONVIF, snapshots, credential bruteforce, and a premium real-time Web Dashboard.

Find, identify, and verify RTSP cameras at scale. From a single IP to millions, with CIDR, ranges, ASN, and Redis queue support.

---

## Quick start

```bash
git clone https://github.com/RshaCuDeVidro/peek.git
cd peek

# Launch the Web Dashboard GUI
python web.py

# Or scan via CLI using a target file
python peek.py ips.txt

# Scan a CIDR block via CLI
python peek.py --target 192.168.1.0/24 -w 200

# Scan an entire ASN via CLI
python peek.py --asn AS28573 -w 300 --save open.txt
```

---

## Features

- **Async I/O Engine** — Built on `asyncio` with configurable concurrency. Probes thousands of targets in seconds.
- **Modern Web Dashboard** — A dark-themed dashboard equipped with Leaflet maps, dynamic telemetry charts (scan rate, status), active console logs, and grouped results.
- **Redis Queue Ingestion (reecanner)** — Native consumer for custom scanners (like `reecanner` SYN scan output). Supports continuous background queue consumption and dynamic concurrent scans.
- **Real-Time Queue Monitor** — A dedicated paginated monitor page (`/redis-queue.html`) capable of handling 10k+ items in the queue with zero lag.
- **Smart Brand Fingerprinting** — RTSP header parsing dynamically identifies Hikvision, Dahua, and Axis brands on the first wave, filtering out incompatible paths to reduce raw connection probes by up to 70%.
- **OpenCV Haar Cascades AI** — Optional Haar Cascade object detection on snapshots to tag and highlight faces or persons. Can be customized via settings.
- **Auto-Export on Completion** — Automatically logs and exports finished scan reports to `exports/` in CSV and/or JSON formats.
- **FFmpeg Snapshots & ONVIF Probing** — Capture JPEG frames and query SOAP `GetDeviceInformation` concurrently with optimized low timeouts.

---

## Web Dashboard & GUI

To start the Web Dashboard, simply execute:

```bash
python web.py
```

This launches a threaded HTTP daemon on **http://127.0.0.1:8000/**.

### Settings Configurations (Gear Icon Modal)
- **Redis Connection:** Configure custom Redis Host, Port, and Database index.
- **Continuous Queue Scan:** Toggle live ingestion of incoming targets in `reecanner:queue`.
- **AI Object Detection Toggles:** Choose whether to run Face Detection, Person Detection, or both.
- **Auto-Export Formats:** Toggle automatic generation of JSON and CSV files on scan completion.

### Live Queue Monitor Page (`/redis-queue.html`)
Open the Live Queue Monitor page in a separate tab to view the live input queue stream, adjust reload intervals (500ms to 5s), paginate through large arrays (10k+ targets) with zero DOM lagging, push test targets, and clear the queue.

---

## CLI Usage

```
python peek.py [input] [options]
```

### Options

| Flag | Arg | Description | Default |
|------|-----|-------------|---------|
| `--target`, `-T` | STR | IP, CIDR, or range (repeatable) | — |
| `--asn` | STR | ASN to fetch prefixes from (repeatable) | — |
| `-w`, `--workers` | INT | Concurrent connections | `50` |
| `-t`, `--timeout` | FLOAT | Timeout in seconds | `5.0` |
| `-p`, `--path` | STR | Extra RTSP path (repeatable) | — |
| `--paths` | FILE | File with paths (one per line) | — |
| `--creds` | FILE | File with credentials (`user:pass` per line) | — |
| `--no-creds` | — | Disable credential bruteforce | off |
| `--port` | INT | Default RTSP port | `554` |
| `--no-onvif` | — | Disable ONVIF probing | off |
| `--snapshots` | — | Capture JPEG frames via ffmpeg | off |
| `--snapshot-dir` | DIR | Output directory for snapshots | `snapshots/` |
| `--json` | FILE | Export results as JSON | — |
| `--csv` | FILE | Export results as CSV | — |
| `--save` | FILE | Save open RTSP URLs | — |
| `--web` | — | Start the web server interface | off |

---

## How it works

### Scan pipeline (4 phases)

1. **Liveness** — Async TCP connection on port 554 (or custom). Dead hosts dropped immediately.
2. **Path probing** — Wave-based `DESCRIBE` on 26 built-in paths. Smart brand fingerprinting skips incompatible paths. Open results are verified via TCP→UDP `PLAY` fallback.
3. **Bruteforce** — Targets returning 401 are tested against default credentials (Basic + Digest).
4. **Enrich** — SOAP ONVIF information query and FFmpeg snapshot capture run concurrently per camera with optimized timeouts.

### Architecture

```
peek.py                     ← launcher
peek/
├── cli.py                  ← argparse + CLI output + export
├── scanner.py              ← async scan pipeline & brand mapping
├── protocol.py             ← RTSP (DESCRIBE/SETUP/PLAY) + auth
├── targets.py              ← IP/CIDR/range/ASN parsing
├── fingerprint.py          ← camera make + SDP codec extraction
├── onvif.py                ← SOAP GetDeviceInformation
├── snapshot.py             ← ffmpeg frame capture
├── db.py                   ← sqlite database history storage
├── ai.py                   ← OpenCV Haar Cascade detection
├── web_server.py           ← multithreaded web server daemon
└── web_assets/             ← index.html, script.js, style.css, redis-queue.html
```

---

## Requirements

- Python 3.10+
- `ffmpeg` (optional, for stream snapshots)
- `whois` (optional, for `--asn` lookup)
- `redis` python package (optional, for Redis queue monitoring)
- `opencv-python` (optional, for Haar Cascade face/person detection)

---

## License

MIT
