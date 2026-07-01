"""CLI argument parsing, output display, and export for peek."""

import argparse
import asyncio
import csv
import json
import sys
import time

from peek.models import CameraResult, ScanConfig
from peek.scanner import scan
from peek.targets import expand_asn, parse_targets, read_creds, read_lines

RTSP_PORT = 554
DEFAULT_TIMEOUT = 5.0
DEFAULT_WORKERS = 50

DEFAULT_PATHS = [
    "/", "/stream", "/live", "/cam/realmonitor", "/onvif1",
    "/Streaming/Channels/101", "/h264", "/av0_0", "/media/video1",
    "/axis-media/media.amp", "/live/ch00_0", "/live/ch01_0",
    "/video1", "/h264.sdp", "/mpeg4", "/mpeg4cif",
    "/11", "/12", "/play1.sdp", "/realplay",
    "/cam/live", "/cam/replay", "/live0", "/live1",
    "/tvSAN", "/doc/page/login.asp",
]

DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "12345"),
    ("admin", "123456"), ("admin", "admin123"), ("admin", ""),
    ("admin", "P@ssw0rd"), ("admin", "ipcam"), ("admin", "888888"),
    ("admin", "666666"), ("admin", "hik12345"), ("admin", "Hikvision123"),
    ("admin", "hikvision"), ("root", "root"), ("root", ""),
    ("root", "password"), ("root", "admin"), ("user", "user"),
    ("user", ""), ("guest", "guest"), ("guest", ""),
    ("service", "service"), ("administrator", ""),
    ("supervisor", "supervisor"), ("demo", "demo"),
]

C = {
    "R": "\033[91m", "G": "\033[92m", "Y": "\033[93m", "B": "\033[94m",
    "M": "\033[95m", "C": "\033[96m", "W": "\033[97m", "D": "\033[90m",
    "Z": "\033[0m", "BOLD": "\033[1m",
}


_CLEAR = "\033[K"  # clear to end of line

def _progress_cb(phase: str, done: int, total: int, extra: str) -> None:
    labels = {"liveness": "Liveness", "probe": "Probe  ", "brute": "Brute  ",
              "enrich": "Enrich ", "done": "Done   "}
    label = labels.get(phase, phase)
    if phase == "done":
        sys.stdout.write(f"\r{_CLEAR}  {C['D']}Time: {extra}{C['Z']}\n")
        sys.stdout.flush()
        return
    if total > 0:
        pct = (done / total) * 100
        bar_w = 20
        filled = int(bar_w * done / total)
        bar = "█" * filled + "░" * (bar_w - filled)
        sys.stdout.write(
            f"\r{_CLEAR}  {C['D']}{label} [{done:>4}/{total:<4}] [{bar}] "
            f"{pct:5.1f}% {extra}{C['Z']}    ")
    else:
        sys.stdout.write(f"\r{_CLEAR}  {C['D']}{label} {extra}{C['Z']}    ")
    sys.stdout.flush()


def _icon(status: str) -> str:
    return {"OPEN": "🔓", "OPEN_AUTH": "🔓", "AUTH": "🔒",
            "CLOSED": "⬛", "ERROR": "❌", "OTHER": "❓"}.get(status, "?")


def _color(status: str) -> str:
    return {"OPEN": C["G"], "OPEN_AUTH": C["G"], "AUTH": C["Y"],
            "CLOSED": C["D"], "ERROR": C["R"], "OTHER": C["M"]}.get(status, C["Z"])


def print_banner() -> None:
    print(f"\n{C['BOLD']}{C['C']}╔{'═' * 72}╗{C['Z']}")
    print(f"{C['BOLD']}{C['C']}║{'Peek (async)':^72}║{C['Z']}")
    print(f"{C['BOLD']}{C['C']}╚{'═' * 72}╝{C['Z']}\n")


def print_config(config: ScanConfig, n_creds: int, sample: int | None = None) -> None:
    print(f"  {C['D']}Targets:     {len(config.targets)}{C['Z']}")
    print(f"  {C['D']}Paths:       {len(config.paths)}{C['Z']}")
    print(f"  {C['D']}Credentials: {n_creds}{C['Z']}")
    print(f"  {C['D']}Workers:     {config.workers}{C['Z']}")
    print(f"  {C['D']}Timeout:     {config.timeout}s{C['Z']}")
    print(f"  {C['D']}ONVIF:       {'ON' if config.onvif else 'OFF'}{C['Z']}")
    print(f"  {C['D']}Snapshots:   {'ON' if config.snapshot else 'OFF'}{C['Z']}")
    if sample:
        print(f"  {C['D']}Sample:      {sample:,} per CIDR{C['Z']}")


def print_results(cameras: list[CameraResult], elapsed: float) -> None:
    print(f"\n\n{C['BOLD']}═══ Results ═══{C['Z']}\n")
    open_cams = [c for c in cameras if c.is_open]

    if open_cams:
        hdr = (f"  {'ST':<4} {'IP':<18} {'MAKE':<14} {'SUMMARY':<12} "
               f"{'STREAM':<18} {'TRANS':<6} {'PATH'}")
        print(f"{C['BOLD']}{hdr}{C['Z']}")
        print(f"  {C['D']}{'─' * 78}{C['Z']}")
        for cam in open_cams:
            b = cam.best_result
            if not b:
                continue
            icon = _icon(b.status)
            color = _color(b.status)
            stream = ""
            if b.sdp_video or b.sdp_audio:
                stream = f"V:{b.sdp_video or '-'} A:{b.sdp_audio or '-'}"
            cred = f" [{b.credential}]" if b.credential else ""
            path = b.path if b.path != "/" else "/"
            transport = b.transport.upper() if b.transport else ""
            make = cam.make[:14]
            print(f"  {icon} {color}{cam.ip:<18}{C['Z']} "
                  f"{C['C']}{make:<14}{C['Z']} "
                  f"{color}{cam.summary_status:<12}{C['Z']} "
                  f"{C['D']}{stream:<18}{C['Z']}"
                  f"{C['D']}{transport:<6}{C['Z']}"
                  f"{C['D']}{path}{cred}{C['Z']}")
            if cam.onvif and cam.onvif.model:
                o = cam.onvif
                print(f"       {C['D']}ONVIF: {o.manufacturer} {o.model} "
                      f"FW:{o.firmware_version}{C['Z']}")
            if cam.snapshot_path:
                print(f"       {C['G']}Snapshot: {cam.snapshot_path}{C['Z']}")
    else:
        print(f"  {C['Y']}No open cameras found.{C['Z']}")

    total = len(cameras)
    open_no = sum(1 for c in cameras if c.best_result and c.best_result.status == "OPEN")
    open_auth = sum(1 for c in cameras
                    if c.best_result and c.best_result.status == "OPEN_AUTH")
    auth_only = sum(1 for c in cameras
                    if c.best_result and c.best_result.status == "AUTH" and not c.is_open)
    closed = sum(1 for c in cameras if c.best_result and c.best_result.status == "CLOSED")
    errors = sum(1 for c in cameras if c.best_result and c.best_result.status == "ERROR")

    print(f"\n{C['BOLD']}═══ Summary ═══{C['Z']}")
    print(f"  Total scanned:       {total}")
    print(f"  {C['G']}Open (no auth):      {open_no}{C['Z']}")
    print(f"  {C['G']}Open (with creds):   {open_auth}{C['Z']}")
    print(f"  {C['Y']}Auth required:       {auth_only}{C['Z']}")
    print(f"  {C['D']}Closed/Filtered:     {closed}{C['Z']}")
    print(f"  {C['R']}Errors:              {errors}{C['Z']}")
    print(f"  Time:                {elapsed:.1f}s")
    if elapsed:
        print(f"  Rate:                {total / elapsed:.1f} IPs/s")
    print()


def save_open(cameras: list[CameraResult], filepath: str) -> None:
    lines = []
    for cam in cameras:
        b = cam.best_result
        if b and b.status in ("OPEN", "OPEN_AUTH"):
            if b.credential and ":" in b.credential:
                u, _, pw = b.credential.partition(":")
                url = f"rtsp://{u}:{pw}@{cam.ip}:{cam.port}{b.path}"
            else:
                url = f"rtsp://{cam.ip}:{cam.port}{b.path}"
            ttag = f" [{b.transport}]" if b.transport else ""
            lines.append(f"{url}  # {cam.make} [{b.status}]{ttag}")
    with open(filepath, "w") as f:
        f.write("\n".join(lines) + "\n" if lines else "")
    print(f"  {C['G']}✓ {len(lines)} URL(s) saved: {filepath}{C['Z']}")


def export_json(cameras: list[CameraResult], filepath: str) -> None:
    data = []
    for cam in cameras:
        b = cam.best_result
        entry = {
            "ip": cam.ip, "port": cam.port, "make": cam.make,
            "status": cam.summary_status, "open": cam.is_open,
            "url": (f"rtsp://{cam.ip}:{cam.port}{b.path}" if b else None),
            "credential": b.credential if b else None,
            "stream": {"video": b.sdp_video, "audio": b.sdp_audio} if b else None,
            "transport": b.transport if b else "",
            "paths_tested": [
                {"path": r.path, "status": r.status, "code": r.status_code,
                 "details": r.details} for r in cam.results
            ],
        }
        if cam.onvif:
            entry["onvif"] = {
                "manufacturer": cam.onvif.manufacturer,
                "model": cam.onvif.model,
                "firmware": cam.onvif.firmware_version,
                "serial": cam.onvif.serial_number,
            }
        if cam.snapshot_path:
            entry["snapshot"] = cam.snapshot_path
        data.append(entry)
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"  {C['G']}✓ JSON exported: {filepath}{C['Z']}")


def export_csv(cameras: list[CameraResult], filepath: str) -> None:
    with open(filepath, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["ip", "port", "make", "status", "open", "path",
                     "credential", "video_codec", "audio_codec",
                     "transport", "onvif_model", "onvif_fw", "details"])
        for cam in cameras:
            b = cam.best_result
            w.writerow([
                cam.ip, cam.port, cam.make, cam.summary_status, cam.is_open,
                b.path if b else "", b.credential if b else "",
                b.sdp_video if b else "", b.sdp_audio if b else "",
                b.transport if b else "",
                cam.onvif.model if cam.onvif else "",
                cam.onvif.firmware_version if cam.onvif else "",
                b.details if b else "",
            ])
    print(f"  {C['G']}✓ CSV exported: {filepath}{C['Z']}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="peek — async RTSP camera scanner with ONVIF, snapshots, CIDR, and ASN support",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python peek.py ips.txt
  python peek.py ips.txt -w 200 --snapshots
  python peek.py --target 192.168.1.0/24 --target 10.0.0.1-50
  python peek.py ips.txt --no-onvif --json out.json
        """,
    )
    parser.add_argument("input", nargs="?", help="File with targets (IP/CIDR/range per line)")
    parser.add_argument("--target", "-T", action="append", dest="extra_targets",
                        help="Target: IP, CIDR, or range (repeatable)")
    parser.add_argument("--asn", action="append", dest="asns",
                        help="ASN to fetch prefixes from (repeatable, e.g. --asn AS28573)")
    parser.add_argument("--limit", type=int, default=0, dest="asn_limit",
                        help="Max prefixes to use per ASN (0 = all)")
    parser.add_argument("--max-cidr", type=int, default=16, dest="max_cidr",
                        help="Skip prefixes larger than /N (default: 16)")
    parser.add_argument("--sample", type=int, default=0, dest="sample_size", metavar="N",
                        help="Sample N IPs from large CIDRs via Feistel (0 = expand all)")
    parser.add_argument("-w", "--workers", type=int, default=DEFAULT_WORKERS,
                        help=f"Concurrency (default: {DEFAULT_WORKERS})")
    parser.add_argument("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help=f"Timeout seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("-p", "--path", action="append", dest="extra_paths",
                        help="Extra RTSP path (repeatable)")
    parser.add_argument("--paths", dest="paths_file", metavar="FILE",
                        help="File with paths (one per line)")
    parser.add_argument("--creds", dest="creds_file", metavar="FILE",
                        help="Credentials file (user:pass per line)")
    parser.add_argument("--no-creds", action="store_true",
                        help="Disable credential bruteforce")
    parser.add_argument("--port", type=int, default=RTSP_PORT,
                        help=f"Default RTSP port (default: {RTSP_PORT})")
    parser.add_argument("--no-onvif", action="store_true",
                        help="Disable ONVIF probing")
    parser.add_argument("--snapshots", action="store_true",
                        help="Capture JPEG snapshots via ffmpeg")
    parser.add_argument("--snapshot-dir", default="snapshots",
                        help="Snapshot output dir (default: snapshots/)")
    parser.add_argument("--json", dest="json_output", metavar="FILE", help="Export JSON")
    parser.add_argument("--csv", dest="csv_output", metavar="FILE", help="Export CSV")
    parser.add_argument("--save", dest="save_file", metavar="FILE",
                        help="Save open RTSP URLs to file")

    args = parser.parse_args()

    paths = list(DEFAULT_PATHS)
    if args.paths_file:
        paths = read_lines(args.paths_file)
    if args.extra_paths:
        paths.extend(args.extra_paths)
    paths = list(dict.fromkeys(paths))

    if args.no_creds:
        creds = []
    elif args.creds_file:
        creds = read_creds(args.creds_file)
    else:
        creds = list(DEFAULT_CREDS)

    # Expand ASNs into CIDR prefixes
    extra_targets = list(args.extra_targets) if args.extra_targets else []
    if args.asns:
        for asn in args.asns:
            print(f"  {C['D']}Fetching prefixes for {asn}...{C['Z']}", end="", flush=True)
            prefixes = expand_asn(asn)
            if prefixes:
                if args.asn_limit and len(prefixes) > args.asn_limit:
                    print(f"\r{C['D']}  {asn}: {len(prefixes)} prefixes, "
                          f"using first {args.asn_limit}{C['Z']}    ")
                    prefixes = prefixes[:args.asn_limit]
                else:
                    print(f"\r{C['D']}  {asn}: {len(prefixes)} prefixes fetched{C['Z']}    ")
                extra_targets.extend(prefixes)
            else:
                print(f"\r{C['R']}  {asn}: no prefixes found{C['Z']}    ")

    sample = args.sample_size if args.sample_size > 0 else None
    targets = parse_targets(args.input, extra_targets if extra_targets else None,
                            args.port, sample)

    config = ScanConfig(
        targets=targets, paths=paths, creds=creds,
        workers=args.workers, timeout=args.timeout,
        onvif=not args.no_onvif, snapshot=args.snapshots,
        snapshot_dir=args.snapshot_dir,
    )

    print_banner()
    print_config(config, len(creds), sample)

    t0 = time.monotonic()
    try:
        cameras = asyncio.run(scan(config, _progress_cb))
    except KeyboardInterrupt:
        print(f"\n{C['D']}Interrupted.{C['Z']}")
        sys.exit(130)

    elapsed = time.monotonic() - t0
    print_results(cameras, elapsed)

    if args.save_file:
        save_open(cameras, args.save_file)
    if args.json_output:
        export_json(cameras, args.json_output)
    if args.csv_output:
        export_csv(cameras, args.csv_output)

    open_count = sum(1 for c in cameras if c.is_open)
    if open_count:
        print(f"  {C['G']}✓ {open_count} open camera(s) found!{C['Z']}\n")
    else:
        print(f"  {C['Y']}No open cameras found.{C['Z']}\n")
    sys.exit(0 if open_count else 1)
