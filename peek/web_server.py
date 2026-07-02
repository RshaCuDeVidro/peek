"""Lightweight HTTP server for peek camera scanner dashboard (zero dependencies)."""

import os
import json
import urllib.parse
import urllib.request
import threading
import asyncio
import time
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from peek.models import ScanConfig
from peek.scanner import scan
from peek.targets import parse_targets, expand_target
from peek.cli import DEFAULT_CREDS, DEFAULT_PATHS
from peek.db import init_db, save_scan, get_latest_scan_results

# Global Web Server State
scan_state = {
    "status": "idle",       # idle, running, completed, stopped, error
    "phase": "idle",        # liveness, probe, brute, enrich, done
    "done": 0,
    "total": 0,
    "extra": "",
    "cameras": [],          # list of serialized cameras
    "logs": [],             # list of string logs
    "rate": 0.0,
    "total_expanded": 0,
    "start_time": 0.0,
}

scan_thread = None
scan_loop = None

# Cache for AI analyzed snapshots to avoid duplicate execution
analyzed_snapshots = {}

SETTINGS_PATH = "settings.json"

def load_settings():
    default_settings = {
        "host": "localhost",
        "port": 6379,
        "db": 0,
        "continuous": False,
        "detect_face": True,
        "detect_person": True,
        "auto_export_json": False,
        "auto_export_csv": False
    }
    if os.path.exists(SETTINGS_PATH):
        try:
            with open(SETTINGS_PATH, "r") as f:
                data = json.load(f)
                # Merge loaded keys into defaults to preserve newer fields
                for k, v in data.items():
                    default_settings[k] = v
        except Exception:
            pass
    return default_settings

def save_settings(s):
    try:
        with open(SETTINGS_PATH, "w") as f:
            json.dump(s, f)
    except Exception:
        pass

app_settings = load_settings()

def get_geoip(ip):
    """Retrieve geolocation details for an IP. Private subnets return local default."""
    if ip.startswith(("127.", "192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")):
        return {
            "status": "success",
            "country": "Rede Local",
            "countryCode": "BR",
            "regionName": "Intranet",
            "city": "IP Privado",
            "lat": -23.5505,  # São Paulo
            "lon": -46.6333,
            "isp": "Local Area Network"
        }
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,lat,lon,isp"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=2.0) as response:
            data = response.read().decode("utf-8")
            return json.loads(data)
    except Exception:
        return {
            "status": "success",
            "country": "Internet",
            "countryCode": "GLO",
            "regionName": "IP Público",
            "city": "Desconhecido",
            "lat": -23.5505,
            "lon": -46.6333,
            "isp": "Provider"
        }

def serialize_camera(cam):
    """Serialize CameraResult instance to a dict and run AI detection on snapshots."""
    best = cam.best_result
    
    # Run OpenCV Haar Cascades AI Detection on snapshot if present
    threats = []
    if cam.snapshot_path and os.path.exists(cam.snapshot_path):
        if cam.snapshot_path not in analyzed_snapshots:
            from peek.ai import detect_objects_in_snapshot
            detected = detect_objects_in_snapshot(
                cam.snapshot_path,
                detect_face=app_settings.get("detect_face", True),
                detect_person=app_settings.get("detect_person", True)
            )
            analyzed_snapshots[cam.snapshot_path] = detected
        threats = analyzed_snapshots[cam.snapshot_path]
        
    geo = get_geoip(cam.ip)
    
    cam_dict = {
        "ip": cam.ip,
        "port": cam.port,
        "make": cam.make,
        "status": cam.summary_status,
        "open": cam.is_open,
        "url": cam.rtsp_url_with_auth if cam.is_open else f"rtsp://{cam.ip}:{cam.port}",
        "credential": best.credential if (best and best.credential) else "",
        "stream": {
            "video": best.sdp_video if best else "",
            "audio": best.sdp_audio if best else ""
        } if best else None,
        "transport": best.transport if best else "",
        "snapshot": cam.snapshot_path if cam.snapshot_path else "",
        "threats": threats,
        "geo": {
            "lat": geo.get("lat"),
            "lon": geo.get("lon"),
            "city": geo.get("city"),
            "country": geo.get("country")
        } if (geo and geo.get("status") == "success") else None
    }
    if cam.onvif:
        cam_dict["onvif"] = {
            "manufacturer": cam.onvif.manufacturer,
            "model": cam.onvif.model,
            "firmware": cam.onvif.firmware_version
        }
    return cam_dict

def run_scan_in_thread(config):
    """Event loop running the scanner in a background thread."""
    global scan_loop, scan_state
    scan_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(scan_loop)
    
    scan_state["status"] = "running"
    scan_state["phase"] = "starting"
    scan_state["done"] = 0
    scan_state["total"] = len(config.targets)
    scan_state["total_expanded"] = len(config.targets)
    scan_state["cameras"] = []
    scan_state["logs"] = ["[SCANNER] Varredura assíncrona iniciada."]
    scan_state["start_time"] = time.monotonic()
    scan_state["rate"] = 0.0

    def progress_cb(phase, done, total, extra):
        scan_state["phase"] = phase
        scan_state["done"] = done
        scan_state["total"] = total
        scan_state["extra"] = extra
        
        # Append progress log
        log_line = f"[{phase.upper()}] {done}/{total} {extra}"
        scan_state["logs"].append(log_line)
        
        # Update speed rate
        elapsed = time.monotonic() - scan_state["start_time"]
        if elapsed > 0.1:
            if phase == "liveness":
                scan_state["rate"] = done / elapsed
            elif phase in ("probe", "brute", "enrich"):
                scan_state["rate"] = scan_state["total_expanded"] / elapsed
                
        # Access config.cameras dynamically in Phase 4 (Enrich)
        cameras = getattr(config, "cameras", [])
        if cameras:
            scan_state["cameras"] = [serialize_camera(c) for c in cameras if c.summary_status not in ("CLOSED", "ERROR")]

    try:
        if app_settings.get("continuous"):
            async def continuous_loader():
                try:
                    import redis
                    r = redis.Redis(
                        host=app_settings.get("host", "localhost"),
                        port=int(app_settings.get("port", 6379)),
                        db=int(app_settings.get("db", 0)),
                        socket_timeout=2.0
                    )
                    while scan_state["status"] == "running":
                        await asyncio.sleep(3.0)
                        if scan_state["status"] != "running":
                            break
                        items = r.lrange('reecanner:queue', 0, -1)
                        if items:
                            r.delete('reecanner:queue')
                            sub_targets = []
                            for item in items:
                                item_str = item.decode('utf-8')
                                if ":" in item_str:
                                    ip, _, p_str = item_str.partition(":")
                                    try:
                                        sub_targets.append((ip, int(p_str)))
                                    except ValueError:
                                        sub_targets.append((ip, 554))
                                else:
                                    sub_targets.append((item_str, 554))
                            
                            if sub_targets:
                                scan_state["logs"].append(f"[REDIS QUEUE] Ingested {len(sub_targets)} new targets. Probing concurrently...")
                                
                                # Define concurrent processor
                                async def process_sub(targets_to_scan):
                                    try:
                                        sub_config = ScanConfig(
                                            targets=targets_to_scan,
                                            paths=config.paths,
                                            creds=config.creds,
                                            workers=config.workers,
                                            timeout=config.timeout,
                                            onvif=config.onvif,
                                            snapshot=config.snapshot,
                                            snapshot_dir=config.snapshot_dir
                                        )
                                        sub_cameras = await scan(sub_config, None)
                                        active_sub = [serialize_camera(c) for c in sub_cameras if c.summary_status not in ("CLOSED", "ERROR")]
                                        
                                        # Log individual discoveries explicitly to the console
                                        for ac in active_sub:
                                            scan_state["logs"].append(f"[REDIS SCANNER] Found active camera: {ac['ip']}:{ac['port']} [{ac['status']}] ({ac.get('make', 'Unknown')})")
                                            
                                        scan_state["cameras"].extend(active_sub)
                                        scan_state["total"] += len(targets_to_scan)
                                        scan_state["total_expanded"] += len(targets_to_scan)
                                        scan_state["done"] += len(targets_to_scan)
                                        scan_state["logs"].append(f"[REDIS QUEUE] Finished concurrent scan of {len(targets_to_scan)} targets ({len(active_sub)} active cameras found).")
                                    except Exception as sub_err:
                                        scan_state["logs"].append(f"[REDIS QUEUE SUB-SCAN ERROR] {sub_err}")
                                
                                scan_loop.create_task(process_sub(sub_targets))
                except Exception as ex:
                    scan_state["logs"].append(f"[REDIS QUEUE ERROR] {ex}")
            
            scan_loop.create_task(continuous_loader())

        # Run scan synchronously inside the thread's event loop
        cameras = scan_loop.run_until_complete(scan(config, progress_cb))
        scan_state["cameras"] = [serialize_camera(c) for c in cameras if c.summary_status not in ("CLOSED", "ERROR")]
        
        # If continuous Redis mode is active, keep the event loop running indefinitely
        if app_settings.get("continuous"):
            async def infinite_wait():
                scan_state["logs"].append("[REDIS QUEUE] Entering continuous monitoring mode. Waiting for new targets...")
                while scan_state["status"] == "running":
                    await asyncio.sleep(1.0)
            scan_loop.run_until_complete(infinite_wait())

        scan_state["status"] = "completed"
        scan_state["phase"] = "done"
        scan_state["logs"].append("[SCANNER] Varredura finalizada com sucesso.")

        # Auto-Export logic
        try:
            if app_settings.get("auto_export_json") or app_settings.get("auto_export_csv"):
                import datetime
                os.makedirs("exports", exist_ok=True)
                timestamp = int(time.time())
                
                if app_settings.get("auto_export_json"):
                    json_path = f"exports/scan_{timestamp}.json"
                    export_data = {
                        "timestamp": datetime.datetime.now().isoformat(),
                        "status": scan_state["status"],
                        "total": scan_state["total"],
                        "cameras": scan_state["cameras"]
                    }
                    with open(json_path, "w", encoding="utf-8") as f:
                        json.dump(export_data, f, indent=2)
                    scan_state["logs"].append(f"[AUTO-EXPORT] Saved JSON results to {json_path}")
                    
                if app_settings.get("auto_export_csv"):
                    csv_path = f"exports/scan_{timestamp}.csv"
                    import csv
                    with open(csv_path, "w", newline="", encoding="utf-8") as f:
                        writer = csv.writer(f)
                        writer.writerow(["IP", "Port", "Manufacturer", "Status", "URL", "Credential"])
                        for cam in scan_state["cameras"]:
                            writer.writerow([
                                cam.get("ip", ""),
                                cam.get("port", ""),
                                cam.get("make", ""),
                                cam.get("status", ""),
                                cam.get("url", ""),
                                cam.get("credential", "")
                            ])
                    scan_state["logs"].append(f"[AUTO-EXPORT] Saved CSV results to {csv_path}")
        except Exception as export_err:
            scan_state["logs"].append(f"[AUTO-EXPORT ERROR] {export_err}")
    except asyncio.CancelledError:
        scan_state["status"] = "stopped"
        scan_state["phase"] = "done"
        scan_state["logs"].append("[SCANNER] Varredura interrompida pelo usuário.")
    except Exception as e:
        scan_state["status"] = "error"
        scan_state["phase"] = "done"
        scan_state["extra"] = str(e)
        scan_state["logs"].append(f"[ERROR] Falha na execução: {e}")
    finally:
        # Save scan to SQLite DB
        try:
            targets_raw = ",".join(f"{ip}:{port}" for ip, port in config.targets) if (hasattr(config, "targets") and config.targets) else ""
            save_scan(
                scan_state["status"],
                scan_state["phase"],
                scan_state["done"],
                scan_state["total"],
                scan_state["rate"],
                targets_raw,
                scan_state["logs"],
                scan_state["cameras"]
            )
        except Exception as db_err:
            scan_state["logs"].append(f"[DATABASE ERROR] Failed to save scan: {db_err}")
            
        scan_loop.close()
        scan_loop = None

class WebRequestHandler(BaseHTTPRequestHandler):
    """Base request handler serving index, CSS, JS, and APIs."""
    
    def log_message(self, format, *args):
        # Prevent default terminal request log noise
        pass

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # Serve static assets
        assets_dir = os.path.join(os.path.dirname(__file__), "web_assets")
        
        if path in ("/", "/index.html"):
            self.serve_file(os.path.join(assets_dir, "index.html"), "text/html")
        elif path in ("/style.css", "/static/css/style.css"):
            self.serve_file(os.path.join(assets_dir, "style.css"), "text/css")
        elif path in ("/script.js", "/static/js/script.js"):
            self.serve_file(os.path.join(assets_dir, "script.js"), "application/javascript")
        elif path == "/redis-queue.html":
            self.serve_file(os.path.join(assets_dir, "redis-queue.html"), "text/html")
        elif path in ("/demo_feed_1.png", "/demo_feed_2.png", "/demo_feed_3.png"):
            filename = path.lstrip("/")
            self.serve_file(os.path.join(assets_dir, filename), "image/png")
            
        # REST APIs
        elif path == "/api/status":
            self.send_json(scan_state)
            
        elif path == "/api/discover":
            from peek.discovery import discover_local_cameras
            discovered = discover_local_cameras()
            self.send_json({"ips": discovered})

        elif path == "/api/redis-settings":
            self.send_json(app_settings)

        elif path == "/api/redis-queue-details":
            query_components = urllib.parse.parse_qs(parsed.query)
            try:
                page = int(query_components.get("page", [1])[0])
                limit = int(query_components.get("limit", [50])[0])
            except ValueError:
                page = 1
                limit = 50
                
            try:
                import redis
                r = redis.Redis(
                    host=app_settings.get("host", "localhost"),
                    port=int(app_settings.get("port", 6379)),
                    db=int(app_settings.get("db", 0)),
                    socket_timeout=1.5
                )
                length = r.llen('reecanner:queue')
                
                # Paginate using lrange
                start_idx = (page - 1) * limit
                end_idx = start_idx + limit - 1
                
                items_bytes = r.lrange('reecanner:queue', start_idx, end_idx) if length > 0 else []
                items = [x.decode('utf-8') for x in items_bytes]
                
                self.send_json({
                    "connected": True,
                    "host": app_settings.get("host"),
                    "port": app_settings.get("port"),
                    "db": app_settings.get("db"),
                    "queue_length": length,
                    "items": items,
                    "page": page,
                    "limit": limit
                })
            except Exception as e:
                self.send_json({
                    "connected": False,
                    "host": app_settings.get("host"),
                    "port": app_settings.get("port"),
                    "db": app_settings.get("db"),
                    "queue_length": 0,
                    "items": [],
                    "error": str(e),
                    "page": page,
                    "limit": limit
                })

        elif path == "/api/geoip":
            query_components = urllib.parse.parse_qs(parsed.query)
            ip = query_components.get("ip", [""])[0]
            if ip:
                self.send_json(get_geoip(ip))
            else:
                self.send_json({"status": "fail", "message": "Missing IP"}, status=400)

        elif path == "/api/scans":
            from peek.db import get_all_scans
            self.send_json(get_all_scans())

        elif path == "/api/redis-status":
            try:
                import redis
                r = redis.Redis(
                    host=app_settings.get("host", "localhost"),
                    port=int(app_settings.get("port", 6379)),
                    db=int(app_settings.get("db", 0)),
                    socket_timeout=1.0
                )
                length = r.llen('reecanner:queue')
                self.send_json({"connected": True, "queue_length": length})
            except Exception as e:
                self.send_json({"connected": False, "queue_length": 0, "error": str(e)})

        elif path == "/api/scan-details":
            query_components = urllib.parse.parse_qs(parsed.query)
            scan_id = query_components.get("id", [""])[0]
            if scan_id:
                from peek.db import get_scan_details
                details = get_scan_details(int(scan_id))
                if details:
                    self.send_json(details)
                else:
                    self.send_json({"status": "fail", "message": "Scan not found"}, status=404)
            else:
                self.send_json({"status": "fail", "message": "Missing scan ID"}, status=400)

        elif path == "/api/stream-live":
            query_components = urllib.parse.parse_qs(parsed.query)
            rtsp_url = query_components.get("url", [""])[0]
            if not rtsp_url:
                self.send_error(400, "Missing RTSP URL")
                return
                
            # Serve stream header
            self.send_response(200)
            self.send_header('Connection', 'close')
            self.send_header('Max-Age', '0')
            self.send_header('Expires', '0')
            self.send_header('Cache-Control', 'no-cache, private, no-store, must-revalidate, max-age=0, post-check=0, pre-check=0')
            self.send_header('Pragma', 'no-cache')
            self.send_header('Content-Type', 'multipart/x-mixed-replace; boundary=frame')
            self.end_headers()

            # Handle Demo stream
            if rtsp_url.startswith("demo"):
                demo_name = "demo_feed_1.png"
                if "dahua" in rtsp_url.lower():
                    demo_name = "demo_feed_2.png"
                elif "intelbras" in rtsp_url.lower():
                    demo_name = "demo_feed_3.png"
                
                filepath = os.path.join(assets_dir, demo_name)
                try:
                    with open(filepath, "rb") as f:
                        img_bytes = f.read()
                    while True:
                        self.wfile.write(b"--frame\r\n")
                        self.wfile.write(b"Content-Type: image/png\r\n")
                        self.wfile.write(f"Content-Length: {len(img_bytes)}\r\n\r\n".encode())
                        self.wfile.write(img_bytes)
                        self.wfile.write(b"\r\n")
                        self.wfile.flush()
                        time.sleep(1.0)
                except Exception:
                    pass
                return

            # Launch ffmpeg transcode process with ultra-low latency flags
            cmd = [
                "ffmpeg",
                "-rtsp_transport", "tcp",
                "-probesize", "32",
                "-analyzeduration", "0",
                "-fflags", "nobuffer",
                "-flags", "low_delay",
                "-i", rtsp_url,
                "-an",
                "-r", "5",
                "-f", "image2pipe",
                "-vcodec", "mjpeg",
                "-"
            ]
            try:
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                buffer = bytearray()
                while True:
                    chunk = process.stdout.read(4096)
                    if not chunk:
                        break
                    buffer.extend(chunk)
                    while True:
                        soi = buffer.find(b'\xff\xd8')
                        if soi == -1:
                            if len(buffer) > 1:
                                del buffer[:-1]
                            break
                        eoi = buffer.find(b'\xff\xd9', soi)
                        if eoi == -1:
                            break
                        jpeg_data = buffer[soi:eoi + 2]
                        del buffer[:eoi + 2]
                        
                        self.wfile.write(b"--frame\r\n")
                        self.wfile.write(b"Content-Type: image/jpeg\r\n")
                        self.wfile.write(f"Content-Length: {len(jpeg_data)}\r\n\r\n".encode())
                        self.wfile.write(jpeg_data)
                        self.wfile.write(b"\r\n")
                        self.wfile.flush()
            except Exception:
                pass
            finally:
                try:
                    process.terminate()
                    process.wait(timeout=1.0)
                except Exception:
                    pass
            
        elif path == "/api/demo":
            demo_data = {
                "cameras": [
                    {
                        "ip": "179.208.77.195",
                        "port": 554,
                        "make": "Hikvision",
                        "status": "OPEN(AUTH)",
                        "open": True,
                        "url": "demo_hikvision",
                        "credential": "admin:admin123",
                        "stream": {"video": "H264", "audio": "PCMU"},
                        "transport": "tcp",
                        "onvif": {
                            "manufacturer": "Hikvision",
                            "model": "DS-2CD2142FWD-I",
                            "firmware": "V5.5.0"
                        },
                        "snapshot": "demo_feed_1.png",
                        "threats": ["person"]
                    },
                    {
                        "ip": "187.105.18.6",
                        "port": 554,
                        "make": "Dahua",
                        "status": "OPEN",
                        "open": True,
                        "url": "demo_dahua",
                        "credential": "",
                        "stream": {"video": "H265", "audio": "PCMU"},
                        "transport": "tcp",
                        "onvif": {
                            "manufacturer": "Dahua",
                            "model": "IPC-HFW1230S",
                            "firmware": "V2.800.0000000.1.R"
                        },
                        "snapshot": "demo_feed_2.png",
                        "threats": []
                    },
                    {
                        "ip": "201.86.112.44",
                        "port": 554,
                        "make": "Intelbras",
                        "status": "OPEN(AUTH)",
                        "open": True,
                        "url": "demo_intelbras",
                        "credential": "admin:admin",
                        "stream": {"video": "H264", "audio": "AAC"},
                        "transport": "udp",
                        "onvif": {
                            "manufacturer": "Intelbras",
                            "model": "VIP 1120 B",
                            "firmware": "V1.0.0"
                        },
                        "snapshot": "demo_feed_3.png",
                        "threats": ["person", "face"]
                    },
                    {
                        "ip": "198.51.100.72",
                        "port": 554,
                        "make": "Axis",
                        "status": "AUTH",
                        "open": False,
                        "url": "rtsp://198.51.100.72:554/axis-media/media.amp",
                        "credential": "",
                        "stream": None,
                        "transport": "",
                        "onvif": None,
                        "snapshot": "",
                        "threats": []
                    }
                ]
            }
            self.send_json(demo_data)
            
        elif path.startswith("/snapshots/"):
            filename = os.path.basename(path)
            snapshot_dir = "snapshots"
            filepath = os.path.join(snapshot_dir, filename)
            if os.path.exists(filepath):
                self.serve_file(filepath, "image/jpeg")
            else:
                self.send_error(404, "Snapshot not found")
        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/scan":
            global scan_thread
            if scan_state["status"] == "running":
                self.send_json({"error": "A scan is already running"}, status=400)
                return

            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")
            try:
                data = json.loads(body)
            except Exception:
                self.send_json({"error": "Invalid JSON body"}, status=400)
                return

            use_redis = bool(data.get("use_redis", False))
            raw_targets = data.get("targets", [])
            workers = int(data.get("workers", 50))
            timeout = float(data.get("timeout", 5.0))
            extra_paths = data.get("paths", [])
            enable_onvif = bool(data.get("onvif", True))
            enable_snapshot = bool(data.get("snapshot", True))

            # Compile credentials
            creds = list(DEFAULT_CREDS)
            
            # Compile paths
            paths = list(DEFAULT_PATHS)
            if extra_paths:
                paths.extend(extra_paths)
            paths = list(dict.fromkeys(paths))

            targets = []
            if use_redis:
                try:
                    import redis
                    r = redis.Redis(host='localhost', port=6379, db=0, socket_timeout=2.0)
                    items = r.lrange('reecanner:queue', 0, -1)
                    if items:
                        # Clear the queue to consume targets
                        r.delete('reecanner:queue')
                        for item in items:
                            item_str = item.decode('utf-8')
                            if ":" in item_str:
                                ip, _, p_str = item_str.partition(":")
                                try:
                                    targets.append((ip, int(p_str)))
                                except ValueError:
                                    targets.append((ip, 554))
                            else:
                                targets.append((item_str, 554))
                except Exception as redis_err:
                    self.send_json({"error": f"Redis connection failed: {redis_err}"}, status=500)
                    return
            else:
                # Expand targets normally
                try:
                    targets = parse_targets(None, raw_targets, 554, None)
                except Exception as e:
                    self.send_json({"error": f"Failed to parse targets: {e}"}, status=400)
                    return

            if not targets:
                self.send_json({"error": "No valid targets found (Redis queue might be empty)"}, status=400)
                return

            # Construct config
            config = ScanConfig(
                targets=targets, paths=paths, creds=creds,
                workers=workers, timeout=timeout,
                onvif=enable_onvif, snapshot=enable_snapshot,
                snapshot_dir="snapshots"
            )

            # Start background thread
            scan_thread = threading.Thread(target=run_scan_in_thread, args=(config,))
            scan_thread.daemon = True
            scan_thread.start()

            self.send_json({"status": "started", "targets_count": len(targets)})
            
        elif path == "/api/stop":
            global scan_loop
            if scan_state["status"] != "running" or scan_loop is None:
                self.send_json({"error": "No scan is currently running"}, status=400)
                return

            # Cancel all tasks in the event loop thread-safely
            def cancel_all():
                for task in asyncio.all_tasks(scan_loop):
                    task.cancel()

            scan_loop.call_soon_threadsafe(cancel_all)
            self.send_json({"status": "stopping"})
            
        elif path == "/api/delete-camera":
            query_components = urllib.parse.parse_qs(parsed.query)
            ip = query_components.get("ip", [""])[0]
            if ip:
                from peek.db import delete_camera_from_db
                try:
                    delete_camera_from_db(ip)
                except Exception as db_err:
                    print(f"[DB DELETE ERROR] {db_err}")
                
                # Also remove from memory
                scan_state["cameras"] = [c for c in scan_state["cameras"] if c["ip"] != ip]
                self.send_json({"status": "success"})
            else:
                self.send_json({"status": "fail", "message": "Missing IP"}, status=400)

        elif path == "/api/redis-settings":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")
            try:
                data = json.loads(body)
                global app_settings
                app_settings["host"] = str(data.get("host", "localhost"))
                app_settings["port"] = int(data.get("port", 6379))
                app_settings["db"] = int(data.get("db", 0))
                app_settings["continuous"] = bool(data.get("continuous", False))
                app_settings["detect_face"] = bool(data.get("detect_face", True))
                app_settings["detect_person"] = bool(data.get("detect_person", True))
                app_settings["auto_export_json"] = bool(data.get("auto_export_json", False))
                app_settings["auto_export_csv"] = bool(data.get("auto_export_csv", False))
                save_settings(app_settings)
                self.send_json({"status": "success", "settings": app_settings})
            except Exception as e:
                self.send_json({"status": "fail", "message": str(e)}, status=400)

        elif path == "/api/redis-clear":
            try:
                import redis
                r = redis.Redis(
                    host=app_settings.get("host", "localhost"),
                    port=int(app_settings.get("port", 6379)),
                    db=int(app_settings.get("db", 0)),
                    socket_timeout=1.5
                )
                r.delete('reecanner:queue')
                self.send_json({"status": "success"})
            except Exception as e:
                self.send_json({"status": "fail", "message": str(e)}, status=500)

        elif path == "/api/redis-push":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")
            try:
                data = json.loads(body)
                target = str(data.get("target", "")).strip()
                if target:
                    import redis
                    r = redis.Redis(
                        host=app_settings.get("host", "localhost"),
                        port=int(app_settings.get("port", 6379)),
                        db=int(app_settings.get("db", 0)),
                        socket_timeout=1.5
                    )
                    r.rpush('reecanner:queue', target)
                    self.send_json({"status": "success"})
                else:
                    self.send_json({"status": "fail", "message": "Missing target"}, status=400)
            except Exception as e:
                self.send_json({"status": "fail", "message": str(e)}, status=500)
        else:
            self.send_error(404, "Not Found")

    def serve_file(self, filepath, content_type):
        """Helper to read and serve static file content."""
        try:
            with open(filepath, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        except Exception:
            self.send_error(500, "Internal Server Error")

    def send_json(self, data, status=200):
        """Helper to format and send JSON responses."""
        content = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

def run_web_server(host="127.0.0.1", port=8000):
    """Initialize and run the HTTP daemon."""
    server_address = (host, port)
    
    # Ensure snapshots dir exists
    os.makedirs("snapshots", exist_ok=True)
    
    # Initialize SQLite Database & load latest scan state
    try:
        init_db()
        latest = get_latest_scan_results()
        if latest:
            scan_state["status"] = latest["status"]
            scan_state["phase"] = latest["phase"]
            scan_state["done"] = latest["done"]
            scan_state["total"] = latest["total"]
            scan_state["total_expanded"] = latest["total"]
            scan_state["rate"] = latest["rate"]
            scan_state["cameras"] = latest["cameras"]
            scan_state["logs"] = [f"[DATABASE] Varredura anterior carregada com sucesso ({len(latest['cameras'])} câmeras)."]
    except Exception as e:
        print(f"[ERROR] Failed to initialize SQLite database: {e}")
    
    httpd = ThreadingHTTPServer(server_address, WebRequestHandler)
    print(f"\n[PEEK WEB] Dashboard running at http://{host}:{port}/")
    print("[PEEK WEB] Press Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[PEEK WEB] Server stopping...")
        httpd.server_close()
