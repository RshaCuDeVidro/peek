import sqlite3
import os
import json

DB_PATH = "peek.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    # Create Scans table (added logs column)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        status TEXT,
        phase TEXT,
        done INTEGER,
        total INTEGER,
        rate REAL,
        targets_raw TEXT,
        logs TEXT
    )
    """)
    
    # Create Cameras table (added geolocation details: lat, lon, city, country)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS cameras (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER,
        ip TEXT,
        port INTEGER,
        make TEXT,
        status TEXT,
        open INTEGER,
        url TEXT,
        credential TEXT,
        video TEXT,
        audio TEXT,
        transport TEXT,
        snapshot TEXT,
        threats TEXT,
        onvif_manufacturer TEXT,
        onvif_model TEXT,
        onvif_firmware TEXT,
        lat REAL,
        lon REAL,
        city TEXT,
        country TEXT,
        FOREIGN KEY (scan_id) REFERENCES scans (id)
    )
    """)
    
    conn.commit()
    conn.close()

def save_scan(status, phase, done, total, rate, targets_raw, logs, cameras):
    conn = get_db()
    cursor = conn.cursor()
    
    logs_str = json.dumps(logs)
    
    # Insert scan
    cursor.execute("""
    INSERT INTO scans (status, phase, done, total, rate, targets_raw, logs)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (status, phase, done, total, rate, targets_raw, logs_str))
    scan_id = cursor.lastrowid
    
    # Insert cameras
    for cam in cameras:
        if cam.get("status") in ("CLOSED", "ERROR"):
            continue
            
        threats_str = json.dumps(cam.get("threats", []))
        onvif = cam.get("onvif") or {}
        geo = cam.get("geo") or {}
        
        cursor.execute("""
        INSERT INTO cameras (
            scan_id, ip, port, make, status, open, url, credential,
            video, audio, transport, snapshot, threats,
            onvif_manufacturer, onvif_model, onvif_firmware,
            lat, lon, city, country
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_id,
            cam.get("ip"),
            cam.get("port"),
            cam.get("make"),
            cam.get("status"),
            1 if cam.get("open") else 0,
            cam.get("url"),
            cam.get("credential"),
            cam.get("stream", {}).get("video") if cam.get("stream") else "",
            cam.get("stream", {}).get("audio") if cam.get("stream") else "",
            cam.get("transport"),
            cam.get("snapshot"),
            threats_str,
            onvif.get("manufacturer"),
            onvif.get("model"),
            onvif.get("firmware"),
            geo.get("lat"),
            geo.get("lon"),
            geo.get("city"),
            geo.get("country")
        ))
        
    conn.commit()
    conn.close()
    return scan_id

def get_latest_scan_results():
    conn = get_db()
    cursor = conn.cursor()
    
    # Get latest scan
    cursor.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1")
    scan = cursor.fetchone()
    if not scan:
        conn.close()
        return None
        
    scan_id = scan["id"]
    
    # Get cameras for latest scan
    cursor.execute("SELECT * FROM cameras WHERE scan_id = ?", (scan_id,))
    cameras_rows = cursor.fetchall()
    
    cameras = []
    for r in cameras_rows:
        try:
            threats = json.loads(r["threats"])
        except Exception:
            threats = []
            
        cam = {
            "ip": r["ip"],
            "port": r["port"],
            "make": r["make"],
            "status": r["status"],
            "open": bool(r["open"]),
            "url": r["url"],
            "credential": r["credential"],
            "stream": {
                "video": r["video"],
                "audio": r["audio"]
            } if (r["video"] or r["audio"]) else None,
            "transport": r["transport"],
            "snapshot": r["snapshot"],
            "threats": threats,
            "geo": {
                "lat": r["lat"],
                "lon": r["lon"],
                "city": r["city"],
                "country": r["country"]
            } if r["lat"] is not None else None
        }
        if r["onvif_manufacturer"] or r["onvif_model"]:
            cam["onvif"] = {
                "manufacturer": r["onvif_manufacturer"],
                "model": r["onvif_model"],
                "firmware": r["onvif_firmware"]
            }
        cameras.append(cam)
        
    try:
        logs = json.loads(scan["logs"])
    except Exception:
        logs = []
        
    res = {
        "id": scan["id"],
        "status": scan["status"],
        "phase": scan["phase"],
        "done": scan["done"],
        "total": scan["total"],
        "rate": scan["rate"],
        "cameras": cameras,
        "targets_raw": scan["targets_raw"],
        "logs": logs
    }
    conn.close()
    return res

def delete_camera_from_db(ip, scan_id=None):
    conn = get_db()
    cursor = conn.cursor()
    if not scan_id:
        # Get latest scan_id
        cursor.execute("SELECT id FROM scans ORDER BY id DESC LIMIT 1")
        scan = cursor.fetchone()
        if scan:
            scan_id = scan["id"]
    
    if scan_id:
        cursor.execute("DELETE FROM cameras WHERE scan_id = ? AND ip = ?", (scan_id, ip))
    conn.commit()
    conn.close()

def get_all_scans():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT s.*, 
               (SELECT COUNT(*) FROM cameras c WHERE c.scan_id = s.id) as cameras_count,
               (SELECT COUNT(*) FROM cameras c WHERE c.scan_id = s.id AND c.open = 1) as open_count
        FROM scans s 
        ORDER BY s.id DESC
    """)
    rows = cursor.fetchall()
    scans = []
    for r in rows:
        scans.append({
            "id": r["id"],
            "timestamp": r["timestamp"],
            "status": r["status"],
            "phase": r["phase"],
            "done": r["done"],
            "total": r["total"],
            "rate": r["rate"],
            "targets_raw": r["targets_raw"],
            "cameras_count": r["cameras_count"],
            "open_count": r["open_count"]
        })
    conn.close()
    return scans

def get_scan_details(scan_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    scan = cursor.fetchone()
    if not scan:
        conn.close()
        return None
        
    cursor.execute("SELECT * FROM cameras WHERE scan_id = ?", (scan_id,))
    cameras_rows = cursor.fetchall()
    
    cameras = []
    for r in cameras_rows:
        try:
            threats = json.loads(r["threats"])
        except Exception:
            threats = []
            
        cam = {
            "ip": r["ip"],
            "port": r["port"],
            "make": r["make"],
            "status": r["status"],
            "open": bool(r["open"]),
            "url": r["url"],
            "credential": r["credential"],
            "stream": {
                "video": r["video"],
                "audio": r["audio"]
            } if (r["video"] or r["audio"]) else None,
            "transport": r["transport"],
            "snapshot": r["snapshot"],
            "threats": threats,
            "geo": {
                "lat": r["lat"],
                "lon": r["lon"],
                "city": r["city"],
                "country": r["country"]
            } if r["lat"] is not None else None
        }
        if r["onvif_manufacturer"] or r["onvif_model"]:
            cam["onvif"] = {
                "manufacturer": r["onvif_manufacturer"],
                "model": r["onvif_model"],
                "firmware": r["onvif_firmware"]
            }
        cameras.append(cam)
        
    try:
        logs = json.loads(scan["logs"])
    except Exception:
        logs = []
        
    res = {
        "id": scan["id"],
        "timestamp": scan["timestamp"],
        "status": scan["status"],
        "phase": scan["phase"],
        "done": scan["done"],
        "total": scan["total"],
        "rate": scan["rate"],
        "cameras": cameras,
        "targets_raw": scan["targets_raw"],
        "logs": logs
    }
    conn.close()
    return res
