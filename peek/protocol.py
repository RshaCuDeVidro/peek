"""Async RTSP protocol implementation with TCP/UDP transport fallback."""

import asyncio
import base64
import hashlib
import re

USER_AGENTS = ["LibVLC/3.0.18", "GStreamer/1.20.0"]


# ── Request builders ──────────────────────────────────────────────────────────

def build_options(host: str, port: int, path: str, cseq: int = 1,
                  auth: str = "") -> bytes:
    return _build(f"OPTIONS rtsp://{host}:{port}{path} RTSP/1.0", cseq, auth).encode()


def build_describe(host: str, port: int, path: str, cseq: int = 1,
                   auth: str = "") -> bytes:
    lines = [
        f"DESCRIBE rtsp://{host}:{port}{path} RTSP/1.0",
        f"CSeq: {cseq}",
        f"User-Agent: {USER_AGENTS[0]}",
        "Accept: application/sdp",
    ]
    if auth:
        lines.append(f"Authorization: {auth}")
    lines.append("")
    lines.append("")
    return "\r\n".join(lines).encode()


def build_setup(host: str, port: int, control_path: str, transport: str,
                cseq: int = 2, auth: str = "") -> bytes:
    """Build SETUP request.
    transport: "tcp" → RTP/AVP/TCP;interleaved=0-1
               "udp" → RTP/AVP;unicast;client_port=5000-5001
    """
    if transport == "udp":
        tspec = "RTP/AVP;unicast;client_port=5000-5001"
    else:
        tspec = "RTP/AVP/TCP;unicast;interleaved=0-1"
    lines = [
        f"SETUP rtsp://{host}:{port}{control_path} RTSP/1.0",
        f"CSeq: {cseq}",
        f"User-Agent: {USER_AGENTS[0]}",
        f"Transport: {tspec}",
    ]
    if auth:
        lines.append(f"Authorization: {auth}")
    lines.append("")
    lines.append("")
    return "\r\n".join(lines).encode()


def build_play(host: str, port: int, path: str, session: str,
               cseq: int = 3, auth: str = "") -> bytes:
    lines = [
        f"PLAY rtsp://{host}:{port}{path} RTSP/1.0",
        f"CSeq: {cseq}",
        f"User-Agent: {USER_AGENTS[0]}",
        f"Session: {session}",
        "Range: npt=0.000-",
    ]
    if auth:
        lines.append(f"Authorization: {auth}")
    lines.append("")
    lines.append("")
    return "\r\n".join(lines).encode()


def _build(first_line: str, cseq: int, auth: str) -> str:
    lines = [first_line, f"CSeq: {cseq}", f"User-Agent: {USER_AGENTS[0]}"]
    if auth:
        lines.append(f"Authorization: {auth}")
    lines.append("")
    lines.append("")
    return "\r\n".join(lines)


# ── Async RTSP sender ─────────────────────────────────────────────────────────

async def send_rtsp(ip: str, port: int, request: bytes,
                    timeout: float) -> dict:
    """Send RTSP request over fresh TCP connection, return parsed response dict."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
    except (asyncio.TimeoutError, OSError) as e:
        return _err(str(e))

    try:
        writer.write(request)
        await writer.drain()

        response = b""
        while b"\r\n\r\n" not in response:
            try:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
                if not chunk:
                    break
                response += chunk
                if len(response) > 65536:  # 64KB header limit
                    return _err("header_too_large")
            except asyncio.TimeoutError:
                break

        if not response:
            return _err("no_response")

        head, _, body_initial = response.partition(b"\r\n\r\n")
        content_length = 0
        for line in head.decode(errors="replace").split("\r\n"):
            if line.lower().startswith("content-length:"):
                try:
                    content_length = int(line.split(":", 1)[1].strip())
                except ValueError:
                    pass
                break

        if content_length > 2 * 1024 * 1024:  # 2MB response body limit
            return _err("body_too_large")

        bytes_needed = content_length - len(body_initial)
        if bytes_needed > 0:
            body_extra = b""
            while len(body_extra) < bytes_needed:
                try:
                    chunk = await asyncio.wait_for(
                        reader.read(min(8192, bytes_needed - len(body_extra))),
                        timeout=timeout,
                    )
                    if not chunk:
                        break
                    body_extra += chunk
                except asyncio.TimeoutError:
                    break
            return parse_response(head + b"\r\n\r\n" + body_initial + body_extra)
        elif content_length > 0:
            return parse_response(head + b"\r\n\r\n" + body_initial[:content_length])

        return parse_response(response)
    except (asyncio.TimeoutError, OSError, ConnectionResetError) as e:
        return _err(str(e))
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


def _err(reason: str) -> dict:
    low = reason.lower()
    if "timeout" in low:
        err = "timeout"
    elif "refused" in low:
        err = "refused"
    elif "reset" in low:
        err = "reset"
    else:
        err = reason or "error"
    return {"status_code": 0, "headers": {}, "body": "",
            "status_line": "", "error": err}


# ── Response parsing ──────────────────────────────────────────────────────────

def parse_response(data: bytes) -> dict:
    """Parse RTSP response bytes into structured dict."""
    text = data.decode(errors="replace")
    head, _, body = text.partition("\r\n\r\n")
    lines = head.split("\r\n")
    status_line = lines[0] if lines else ""
    parts = status_line.split(" ", 2)
    code = int(parts[1]) if (len(parts) >= 2 and parts[1].isdigit()) else 0
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return {"status_line": status_line, "status_code": code,
            "headers": headers, "body": body, "error": ""}


def classify_response(resp: dict) -> str:
    """Classify RTSP response into a status category string."""
    code = resp.get("status_code", 0)
    err = resp.get("error", "")
    if err in ("timeout", "refused", "no_response"):
        return "CLOSED"
    if err:
        return "ERROR"
    if code == 200:
        return "OPEN"
    if code == 401:
        return "AUTH"
    if code > 0:
        return "OTHER"
    return "ERROR"


# ── Authentication ────────────────────────────────────────────────────────────

def parse_www_authenticate(header: str) -> dict:
    """Parse WWW-Authenticate header into scheme + params."""
    if not header:
        return {"scheme": ""}
    scheme = header.split()[0].lower() if header.split() else ""
    info: dict = {"scheme": scheme}
    rest = header[len(scheme):].strip()
    for m in re.finditer(r'(\w+)\s*=\s*(?:"([^"]*)"|([^,\s]+))', rest):
        key = m.group(1).lower()
        val = m.group(2) if m.group(2) is not None else m.group(3)
        info[key] = val
    return info


def basic_auth(user: str, password: str) -> str:
    return f"Basic {base64.b64encode(f'{user}:{password}'.encode()).decode()}"


def digest_auth(user: str, password: str, method: str, uri: str,
                realm: str, nonce: str, algorithm: str = "MD5") -> str:
    ha1 = hashlib.md5(f"{user}:{realm}:{password}".encode()).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    resp = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
    return (f'Digest username="{user}", realm="{realm}", nonce="{nonce}", '
            f'uri="{uri}", response="{resp}", algorithm={algorithm or "MD5"}')


def build_auth_header(auth_info: dict, user: str, password: str,
                      method: str, uri: str) -> str:
    scheme = auth_info.get("scheme", "")
    if scheme == "digest":
        return digest_auth(user, password, method, uri,
                           auth_info.get("realm", ""),
                           auth_info.get("nonce", ""),
                           auth_info.get("algorithm", "MD5"))
    return basic_auth(user, password)


# ── Port liveness ─────────────────────────────────────────────────────────────

async def check_port(ip: str, port: int, timeout: float) -> bool:
    """Async check if a TCP port is open."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False
