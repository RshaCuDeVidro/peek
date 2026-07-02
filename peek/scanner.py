"""Async RTSP scanner — liveness, path probing, credential bruteforce, enrich."""

import asyncio
import time
from collections import defaultdict
from typing import Any

from peek.models import CameraResult, PathResult, ScanConfig
from peek.protocol import (
    build_auth_header, build_describe, build_options, build_play, build_setup,
    check_port, classify_response, parse_www_authenticate, send_rtsp,
)
from peek.fingerprint import (
    extract_control_url, fingerprint, is_valid_sdp, parse_sdp,
)
from peek.onvif import probe_onvif
from peek.snapshot import capture_snapshot

ProgressCb = Any  # callable(phase, done, total, extra) | None


# ── Verify playable (async, TCP → UDP fallback) ───────────────────────────────

async def _verify_playable(ip: str, port: int, path: str, sdp_body: str,
                           timeout: float, auth: str = "") -> tuple[bool, str, str]:
    """Confirm stream is playable via SETUP. Returns (ok, message, transport)."""
    if not is_valid_sdp(sdp_body):
        return False, "response is not a valid SDP", ""

    # Quick OPTIONS re-check (with auth retry if 401)
    opts = await send_rtsp(ip, port, build_options(ip, port, path), timeout)
    if opts.get("status_code") == 401 and auth:
        opts = await send_rtsp(ip, port, build_options(ip, port, path, auth=auth), timeout)
        if opts.get("status_code") == 401:
            return False, "OPTIONS rejects credentials", ""

    control = extract_control_url(sdp_body, path)

    # ── Try TCP SETUP ──
    setup = await send_rtsp(ip, port, build_setup(ip, port, control, "tcp"), timeout)

    if setup.get("status_code") == 401:
        if auth:
            setup = await send_rtsp(
                ip, port, build_setup(ip, port, control, "tcp", auth=auth), timeout)
            if setup.get("status_code") == 401:
                return False, "SETUP rejects credentials (TCP)", ""
            if setup.get("status_code") == 200:
                return await _try_play(ip, port, path, setup, timeout, auth, "tcp")
        else:
            return False, "SETUP requires auth", setup["headers"].get("www-authenticate", "")

    if setup.get("status_code") == 200:
        return await _try_play(ip, port, path, setup, timeout, auth, "tcp")

    # ── TCP failed → UDP fallback ──
    setup_udp = await send_rtsp(ip, port, build_setup(ip, port, control, "udp"), timeout)

    if setup_udp.get("status_code") == 401:
        if auth:
            setup_udp = await send_rtsp(
                ip, port, build_setup(ip, port, control, "udp", auth=auth), timeout)
            if setup_udp.get("status_code") == 401:
                return False, "SETUP rejects credentials (UDP)", ""
            if setup_udp.get("status_code") == 200:
                return await _try_play(ip, port, path, setup_udp, timeout, auth, "udp")
        return False, "SETUP requires auth (UDP)", ""

    if setup_udp.get("status_code") == 200:
        return await _try_play(ip, port, path, setup_udp, timeout, auth, "udp")

    # Neither transport worked, but DESCRIBE came back 200
    return True, f"DESCRIBE ok (SETUP {setup.get('status_code', '?')})", ""


async def _try_play(ip: str, port: int, path: str, setup: dict,
                    timeout: float, auth: str, transport: str) -> tuple[bool, str, str]:
    """Send PLAY after successful SETUP, returns (ok, msg, transport)."""
    session = setup["headers"].get("session", "").split(";")[0].strip()
    if session:
        play = await send_rtsp(
            ip, port, build_play(ip, port, path, session, auth=auth), timeout)
        if play.get("status_code") == 200:
            tag = " with auth" if auth else ""
            return True, f"SETUP+PLAY 200 ({transport}){tag}", transport
    return True, f"SETUP 200 ({transport})", transport


# ── Probe helpers ─────────────────────────────────────────────────────────────

async def _probe_path(ip: str, port: int, path: str, timeout: float,
                      target_done: dict, target_401: dict, target_has_responded: dict,
                      target_manufacturer: dict, sem: asyncio.Semaphore) -> PathResult | None:
    """Probe one path on a target, returning PathResult or None if early-exit."""
    target_key = (ip, port)
    if target_key in target_done or target_key in target_401:
        return None

    async with sem:
        resp = await send_rtsp(ip, port, build_describe(ip, port, path), timeout)

    # Detect brand for smart fingerprinting
    server = resp.get("headers", {}).get("server", "").lower() if resp.get("headers") else ""
    www_auth = resp.get("headers", {}).get("www-authenticate", "").lower() if resp.get("headers") else ""
    brand = None
    if any(k in server or k in www_auth for k in ("hikvision", "dvrdvs", "dvs", "activex")):
        brand = "hikvision"
    elif any(k in server or k in www_auth for k in ("dahua", "dss", "playback", "dvr-")):
        brand = "dahua"
    elif "axis" in server:
        brand = "axis"
    if brand:
        target_manufacturer[target_key] = brand

    status = classify_response(resp)
    server = resp["headers"].get("server", "")

    if status == "OPEN":
        target_has_responded[target_key] = True
        sdp_body = resp.get("body", "")
        video, audio = parse_sdp(sdp_body)
        confirmed, msg, transport = await _verify_playable(ip, port, path, sdp_body, timeout)
        if confirmed:
            target_done[target_key] = ("OPEN", path, server, video, audio, "", transport)
            return PathResult(path=path, status="OPEN", status_code=200,
                              server=server, sdp_video=video, sdp_audio=audio,
                              details=msg, transport=transport)
        else:
            if target_key not in target_401:
                target_401[target_key] = (path, server, msg)
            return PathResult(path=path, status="AUTH", status_code=401,
                              server=server, details=f"DESCRIBE 200 but {msg}")

    if status == "AUTH":
        target_has_responded[target_key] = True
        if target_key not in target_401:
            target_401[target_key] = (path, server, resp["headers"].get("www-authenticate", ""))
        return PathResult(path=path, status="AUTH", status_code=401,
                          server=server, details="requires authentication")

    if status == "OTHER":
        target_has_responded[target_key] = True
        return PathResult(path=path, status="OTHER",
                          status_code=resp.get("status_code", 0),
                          server=server, details=f"HTTP {resp.get('status_code', 0)}")

    if target_key not in target_has_responded:
        target_done[target_key] = ("CLOSED", path, server, "", "", "", "")

    return PathResult(path=path, status=status, details=resp.get("error", ""))


async def _probe_cred(ip: str, port: int, path: str, auth_header: str,
                      auth_info: dict, cred_label: str, server: str, target_done: dict,
                      sem: asyncio.Semaphore, timeout: float, all_paths: list[str]) -> PathResult | None:
    """Try one credential pair, returning PathResult or None."""
    target_key = (ip, port)
    if target_key in target_done:
        return None

    async with sem:
        resp = await send_rtsp(
            ip, port, build_describe(ip, port, path, auth=auth_header), timeout)

    status_code = resp.get("status_code", 0)
    if status_code == 0 or status_code == 401:
        return None

    # Credentials worked! Check if this path is playable.
    sdp_body = resp.get("body", "")
    video, audio = parse_sdp(sdp_body)
    confirmed, msg, transport = await _verify_playable(
        ip, port, path, sdp_body, timeout, auth=auth_header)

    if confirmed:
        target_done[target_key] = ("OPEN_AUTH", path, server, video, audio, cred_label, transport)
        return PathResult(path=path, status="OPEN_AUTH", status_code=200,
                          server=server, credential=cred_label,
                          sdp_video=video, sdp_audio=audio,
                          details=f"opened with {cred_label} ({msg})",
                          transport=transport)

    # Credentials accepted but this path is not playable (e.g. 404 or non-playable 200).
    # Try other paths using this correct credential!
    user, _, password = cred_label.partition(":")
    for alt_path in all_paths:
        if alt_path == path:
            continue
        if target_key in target_done:
            return None

        alt_uri = f"rtsp://{ip}:{port}{alt_path}"
        alt_ah = build_auth_header(auth_info, user, password, "DESCRIBE", alt_uri)

        async with sem:
            alt_resp = await send_rtsp(
                ip, port, build_describe(ip, port, alt_path, auth=alt_ah), timeout)

        if alt_resp.get("status_code") == 200:
            alt_sdp = alt_resp.get("body", "")
            alt_video, alt_audio = parse_sdp(alt_sdp)
            alt_confirmed, alt_msg, alt_transport = await _verify_playable(
                ip, port, alt_path, alt_sdp, timeout, auth=alt_ah)
            if alt_confirmed:
                target_done[target_key] = ("OPEN_AUTH", alt_path, server, alt_video, alt_audio, cred_label, alt_transport)
                return PathResult(path=alt_path, status="OPEN_AUTH", status_code=200,
                                  server=server, credential=cred_label,
                                  sdp_video=alt_video, sdp_audio=alt_audio,
                                  details=f"opened with {cred_label} ({alt_msg})",
                                  transport=alt_transport)

    return PathResult(path=path, status="AUTH", status_code=status_code, server=server,
                      details=f"DESCRIBE accepted {cred_label} but not playable")


# ── Main scanner ──────────────────────────────────────────────────────────────

async def scan(config: ScanConfig, progress: ProgressCb = None) -> list[CameraResult]:
    """Run full async RTSP scan pipeline. Returns list of CameraResult."""
    targets = config.targets
    timeout = config.timeout
    sem = asyncio.Semaphore(config.workers)

    target_done: dict = {}
    target_401: dict = {}
    ip_results: dict[tuple[str, int], list[PathResult]] = defaultdict(list)

    t_start = time.monotonic()

    # ── Phase 1: Liveness ─────────────────────────────────────────────────
    _pb(progress, "liveness", 0, len(targets), "starting")
    alive: list[tuple[str, int]] = []

    async def _check_one(ip: str, port: int) -> tuple[str, int, bool]:
        async with sem:
            ok = await check_port(ip, port, min(timeout, 3.0))
            return ip, port, ok

    done = 0
    for coro in asyncio.as_completed([_check_one(ip, p) for ip, p in targets]):
        ip, port, ok = await coro
        done += 1
        target_key = (ip, port)
        if ok:
            alive.append((ip, port))
        else:
            ip_results[target_key].append(PathResult(path="/", status="CLOSED", details="port_closed"))
        if done % 50 == 0 or ok:
            _pb(progress, "liveness", done, len(targets), f"alive={len(alive)}")

    _pb(progress, "liveness", len(targets), len(targets),
        f"done ({len(alive)}/{len(targets)} alive)")

    # ── Phase 2: Path probing (in waves) ──────────────────────────────────
    target_has_responded: dict[tuple[str, int], bool] = {}
    target_manufacturer: dict[tuple[str, int], str] = {}
    
    # Path compatibility mapping
    PATH_BRANDS = {
        "/Streaming/Channels/101": "hikvision",
        "/h264": "hikvision",
        "/11": "hikvision",
        "/12": "hikvision",
        "/cam/realmonitor": "dahua",
        "/cam/live": "dahua",
        "/cam/replay": "dahua",
        "/axis-media/media.amp": "axis",
        "/axis-media/media.3gp": "axis",
    }
    
    total_p2 = len(alive) * len(config.paths)
    _pb(progress, "probe", 0, total_p2, f"on {len(alive)} targets")

    p2_done = 0
    for path_idx, path in enumerate(config.paths):
        path_brand = PATH_BRANDS.get(path)
        targets_to_probe = []
        for ip, port in alive:
            target_key = (ip, port)
            if target_key in target_done or target_key in target_401:
                continue
            
            # Skip incompatible paths based on detected brand fingerprint
            if path_brand:
                detected_brand = target_manufacturer.get(target_key)
                if detected_brand and detected_brand != path_brand:
                    continue
            targets_to_probe.append((ip, port))

        if not targets_to_probe:
            break

        async def _probe_tracked(ip: str, port: int, path: str) -> tuple[tuple[str, int], PathResult | None]:
            result = await _probe_path(ip, port, path, timeout, target_done, target_401,
                                       target_has_responded, target_manufacturer, sem)
            return (ip, port), result

        tasks = [_probe_tracked(ip, port, path) for ip, port in targets_to_probe]
        for coro in asyncio.as_completed(tasks):
            target_key, result = await coro
            p2_done += 1
            if result is not None:
                ip_results[target_key].append(result)
            if p2_done % 10 == 0:
                _pb(progress, "probe", p2_done, total_p2, "")

    _pb(progress, "probe", total_p2, total_p2, "done")

    # ── Phase 3: Credential bruteforce ────────────────────────────────────
    auth_targets = {target_key: info for target_key, info in target_401.items()
                    if target_key not in target_done and config.creds}

    if auth_targets and config.creds:
        cred_tasks: list[tuple] = []
        for (ip, port), (path, server, www_auth) in auth_targets.items():
            auth_info = parse_www_authenticate(www_auth)
            if not path:
                path = "/"
            uri = f"rtsp://{ip}:{port}{path}"
            for user, password in config.creds:
                ah = build_auth_header(auth_info, user, password, "DESCRIBE", uri)
                cred_tasks.append((ip, port, path, ah, auth_info, f"{user}:{password}", server))

        total_p3 = len(cred_tasks)
        found_p3 = 0
        _pb(progress, "brute", 0, total_p3,
            f"{len(auth_targets)} target(s) x {len(config.creds)} creds")

        p3_done = 0
        if cred_tasks:
            async def _cred_tracked(args: tuple) -> tuple[tuple[str, int], PathResult | None]:
                ip, port, path, ah, ai, cl, srv = args
                result = await _probe_cred(ip, port, path, ah, ai, cl, srv, target_done, sem, timeout, config.paths)
                return (ip, port), result

            for coro in asyncio.as_completed([_cred_tracked(t) for t in cred_tasks]):
                target_key, result = await coro
                p3_done += 1
                if result is not None:
                    ip_results[target_key].append(result)
                    if result.status == "OPEN_AUTH":
                        found_p3 += 1
                if p3_done % 50 == 0:
                    _pb(progress, "brute", p3_done, total_p3, f"found={found_p3}")

        _pb(progress, "brute", total_p3, total_p3, f"done ({found_p3} found)")

    # ── Build CameraResult objects ────────────────────────────────────────
    cameras: list[CameraResult] = []
    for ip, port in targets:
        target_key = (ip, port)
        cam = CameraResult(ip=ip, port=port)
        cam.results = ip_results.get(target_key, [])
        servers = {r.server for r in cam.results if r.server}
        cam.make = fingerprint(servers.pop()) if servers else "Unknown"

        if target_key in target_done and not cam.open_result:
            status, path, server, video, audio, cred, transport = target_done[target_key]
            if status in ("OPEN", "OPEN_AUTH"):
                cam.results.append(PathResult(
                    path=path, status=status, status_code=200,
                    server=server, credential=cred or "",
                    sdp_video=video, sdp_audio=audio,
                    details="no auth" if not cred else f"opened with {cred}",
                    transport=transport,
                ))
        cameras.append(cam)

    config.cameras = cameras

    # ── Phase 4: Enrich (ONVIF + Snapshots) ───────────────────────────────
    open_cams = [cam for cam in cameras if cam.is_open]
    if open_cams:
        total_p4 = len(open_cams)
        _pb(progress, "enrich", 0, total_p4, f"{total_p4} cameras")

        p4_done = 0
        async def _enrich_one(cam: CameraResult) -> None:
            async with sem:
                onvif_task = asyncio.create_task(probe_onvif(cam.ip, timeout=1.5)) if config.onvif else None
                snap_task = asyncio.create_task(capture_snapshot(cam.rtsp_url_with_auth, config.snapshot_dir, timeout=8.0)) if config.snapshot else None
                
                if onvif_task and snap_task:
                    res_onvif, res_snap = await asyncio.gather(onvif_task, snap_task, return_exceptions=True)
                elif onvif_task:
                    res_onvif = await onvif_task
                    res_snap = None
                elif snap_task:
                    res_snap = await snap_task
                    res_onvif = None
                else:
                    res_onvif = res_snap = None
                
                # Process ONVIF info
                if res_onvif and not isinstance(res_onvif, Exception):
                    cam.onvif = res_onvif
                    if res_onvif.manufacturer:
                        cam.make = res_onvif.manufacturer
                        
                # Process snapshot info
                if res_snap and not isinstance(res_snap, Exception):
                    cam.snapshot_path = res_snap

        tasks = [_enrich_one(cam) for cam in open_cams]
        for coro in asyncio.as_completed(tasks):
            await coro
            p4_done += 1
            _pb(progress, "enrich", p4_done, total_p4, "")

        _pb(progress, "enrich", total_p4, total_p4, "done")

    elapsed = time.monotonic() - t_start
    _pb(progress, "done", 0, 0, f"{elapsed:.1f}s")

    return cameras


# Sentinel port used above
RTSP_PORT = 554


def _pb(progress: ProgressCb, phase: str, done: int, total: int, extra: str) -> None:
    if progress:
        progress(phase, done, total, extra)
