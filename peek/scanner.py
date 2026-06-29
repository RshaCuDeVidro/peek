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
                      ip_done: dict, ip_401: dict, ip_has_responded: dict,
                      sem: asyncio.Semaphore) -> PathResult | None:
    """Probe one path on a target, returning PathResult or None if early-exit."""
    if ip in ip_done:
        return None

    async with sem:
        resp = await send_rtsp(ip, port, build_describe(ip, port, path), timeout)

    status = classify_response(resp)
    server = resp["headers"].get("server", "")

    if status == "OPEN":
        ip_has_responded[ip] = True
        sdp_body = resp.get("body", "")
        video, audio = parse_sdp(sdp_body)
        confirmed, msg, transport = await _verify_playable(ip, port, path, sdp_body, timeout)
        if confirmed:
            ip_done[ip] = ("OPEN", path, server, video, audio, "", transport)
            return PathResult(path=path, status="OPEN", status_code=200,
                              server=server, sdp_video=video, sdp_audio=audio,
                              details=msg, transport=transport)
        else:
            if ip not in ip_401:
                ip_401[ip] = (path, server, msg)
            return PathResult(path=path, status="AUTH", status_code=401,
                              server=server, details=f"DESCRIBE 200 but {msg}")

    if status == "AUTH":
        ip_has_responded[ip] = True
        if ip not in ip_401:
            ip_401[ip] = (path, server, resp["headers"].get("www-authenticate", ""))
        return PathResult(path=path, status="AUTH", status_code=401,
                          server=server, details="requires authentication")

    if status == "OTHER":
        ip_has_responded[ip] = True
        return PathResult(path=path, status="OTHER",
                          status_code=resp.get("status_code", 0),
                          server=server, details=f"HTTP {resp.get('status_code', 0)}")

    if ip not in ip_has_responded:
        ip_done[ip] = ("CLOSED", path, server, "", "", "", "")

    return PathResult(path=path, status=status, details=resp.get("error", ""))


async def _probe_cred(ip: str, port: int, path: str, auth_header: str,
                      cred_label: str, server: str, ip_done: dict,
                      sem: asyncio.Semaphore, timeout: float) -> PathResult | None:
    """Try one credential pair, returning PathResult or None."""
    if ip in ip_done:
        return None

    async with sem:
        resp = await send_rtsp(
            ip, port, build_describe(ip, port, path, auth=auth_header), timeout)

    if resp.get("status_code") != 200:
        return None

    sdp_body = resp.get("body", "")
    video, audio = parse_sdp(sdp_body)
    confirmed, msg, transport = await _verify_playable(
        ip, port, path, sdp_body, timeout, auth=auth_header)

    if confirmed:
        ip_done[ip] = ("OPEN_AUTH", path, server, video, audio, cred_label, transport)
        return PathResult(path=path, status="OPEN_AUTH", status_code=200,
                          server=server, credential=cred_label,
                          sdp_video=video, sdp_audio=audio,
                          details=f"opened with {cred_label} ({msg})",
                          transport=transport)
    return PathResult(path=path, status="AUTH", status_code=401, server=server,
                      details=f"DESCRIBE accepted {cred_label} but {msg}")


# ── Main scanner ──────────────────────────────────────────────────────────────

async def scan(config: ScanConfig, progress: ProgressCb = None) -> list[CameraResult]:
    """Run full async RTSP scan pipeline. Returns list of CameraResult."""
    targets = config.targets
    timeout = config.timeout
    sem = asyncio.Semaphore(config.workers)

    ip_done: dict = {}
    ip_401: dict = {}
    ip_results: dict[str, list[PathResult]] = defaultdict(list)

    t_start = time.monotonic()

    # ── Phase 1: Liveness ─────────────────────────────────────────────────
    _pb(progress, "liveness", 0, len(targets), "starting")
    alive: list[tuple[str, int]] = []

    async def _check_one(ip: str, port: int) -> tuple[str, int, bool]:
        ok = await check_port(ip, port, min(timeout, 3.0))
        return ip, port, ok

    done = 0
    for coro in asyncio.as_completed([_check_one(ip, p) for ip, p in targets]):
        ip, port, ok = await coro
        done += 1
        if ok:
            alive.append((ip, port))
        else:
            ip_results[ip].append(PathResult(path="/", status="CLOSED", details="port_closed"))
        if done % 50 == 0 or ok:
            _pb(progress, "liveness", done, len(targets), f"alive={len(alive)}")

    _pb(progress, "liveness", len(targets), len(targets),
        f"done ({len(alive)}/{len(targets)} alive)")

    # ── Phase 2: Path probing ─────────────────────────────────────────────
    ip_has_responded: dict[str, bool] = {}
    probes = [(ip, port, path) for path in config.paths for ip, port in alive]
    total_p2 = len(probes)
    _pb(progress, "probe", 0, total_p2, f"on {len(alive)} targets")

    p2_done = 0
    if probes:
        async def _probe_tracked(ip: str, port: int, path: str) -> tuple[str, PathResult | None]:
            result = await _probe_path(ip, port, path, timeout, ip_done, ip_401,
                                       ip_has_responded, sem)
            return ip, result

        for coro in asyncio.as_completed(
            [_probe_tracked(ip, port, path) for ip, port, path in probes]
        ):
            ip, result = await coro
            p2_done += 1
            if result is not None:
                ip_results[ip].append(result)
            if p2_done % 10 == 0:
                _pb(progress, "probe", p2_done, total_p2, "")

    _pb(progress, "probe", total_p2, total_p2, "done")

    # ── Phase 3: Credential bruteforce ────────────────────────────────────
    auth_targets = {ip: info for ip, info in ip_401.items()
                    if ip not in ip_done and config.creds}

    if auth_targets and config.creds:
        cred_tasks: list[tuple] = []
        for ip, (path, server, www_auth) in auth_targets.items():
            auth_info = parse_www_authenticate(www_auth)
            if not path:
                path = "/"
            tp = 554
            for aip, aport in alive:
                if aip == ip:
                    tp = aport
                    break
            uri = f"rtsp://{ip}:{tp}{path}"
            for user, password in config.creds:
                ah = build_auth_header(auth_info, user, password, "DESCRIBE", uri)
                cred_tasks.append((ip, tp, path, ah, f"{user}:{password}", server))

        total_p3 = len(cred_tasks)
        found_p3 = 0
        _pb(progress, "brute", 0, total_p3,
            f"{len(auth_targets)} IPs x {len(config.creds)} creds")

        p3_done = 0
        if cred_tasks:
            async def _cred_tracked(args: tuple) -> tuple[str, PathResult | None]:
                ip, tp, path, ah, cl, srv = args
                result = await _probe_cred(ip, tp, path, ah, cl, srv, ip_done, sem, timeout)
                return ip, result

            for coro in asyncio.as_completed([_cred_tracked(t) for t in cred_tasks]):
                ip, result = await coro
                p3_done += 1
                if result is not None:
                    ip_results[ip].append(result)
                    if result.status == "OPEN_AUTH":
                        found_p3 += 1
                if p3_done % 50 == 0:
                    _pb(progress, "brute", p3_done, total_p3, f"found={found_p3}")

        _pb(progress, "brute", total_p3, total_p3, f"done ({found_p3} found)")

    # ── Build CameraResult objects ────────────────────────────────────────
    all_ips = set(t[0] for t in targets)
    cameras: dict[str, CameraResult] = {}
    for ip in all_ips:
        cam = CameraResult(ip=ip)
        for tip, tp in targets:
            if tip == ip:
                cam.port = tp
                break
        cam.results = ip_results.get(ip, [])
        servers = {r.server for r in cam.results if r.server}
        cam.make = fingerprint(servers.pop()) if servers else "Unknown"

        if ip in ip_done and not cam.open_result:
            status, path, server, video, audio, cred, transport = ip_done[ip]
            if status in ("OPEN", "OPEN_AUTH"):
                cam.results.append(PathResult(
                    path=path, status=status, status_code=200,
                    server=server, credential=cred or "",
                    sdp_video=video, sdp_audio=audio,
                    details="no auth" if not cred else f"opened with {cred}",
                    transport=transport,
                ))
        cameras[ip] = cam

    # ── Phase 4: Enrich (ONVIF + Snapshots) ───────────────────────────────
    open_cams = {ip: cam for ip, cam in cameras.items() if cam.is_open}
    if open_cams:
        total_p4 = len(open_cams)
        _pb(progress, "enrich", 0, total_p4, f"{total_p4} cameras")

        p4_done = 0
        for ip, cam in open_cams.items():
            if config.onvif:
                onvif_info = await probe_onvif(ip)
                if onvif_info:
                    cam.onvif = onvif_info
                    if onvif_info.manufacturer:
                        cam.make = onvif_info.manufacturer

            if config.snapshot:
                snap = await capture_snapshot(cam.rtsp_url_with_auth, config.snapshot_dir)
                if snap:
                    cam.snapshot_path = snap

            p4_done += 1
            if p4_done % 5 == 0:
                _pb(progress, "enrich", p4_done, total_p4, "")

        _pb(progress, "enrich", total_p4, total_p4, "done")

    elapsed = time.monotonic() - t_start
    _pb(progress, "done", 0, 0, f"{elapsed:.1f}s")

    return [cameras[ip] for ip in all_ips]


# Sentinel port used above
RTSP_PORT = 554


def _pb(progress: ProgressCb, phase: str, done: int, total: int, extra: str) -> None:
    if progress:
        progress(phase, done, total, extra)
