"""FFmpeg snapshot capture for verified RTSP streams."""

import asyncio
import os
import shutil
import sys

FFMPEG_TIMEOUT = 10.0


async def capture_snapshot(rtsp_url: str, output_dir: str,
                           timeout: float = FFMPEG_TIMEOUT) -> str | None:
    """Capture a single JPEG frame from an RTSP stream using ffmpeg.

    Returns path to JPEG on success, None on failure.
    """
    if not shutil.which("ffmpeg"):
        return None

    os.makedirs(output_dir, exist_ok=True)

    # Derive safe filename from URL (IP + path)
    # rtsp://guest:guest@10.0.0.1:554/stream → 10.0.0.1_554_stream.jpg
    clean = rtsp_url
    # Strip protocol and auth
    if "@" in clean:
        clean = clean.split("@", 1)[1]
    else:
        clean = clean.replace("rtsp://", "")
    safe_name = clean.replace(":", "_").replace("/", "_").replace(".", "_")
    if len(safe_name) > 100:
        safe_name = safe_name[:100]
    out_path = os.path.join(output_dir, f"{safe_name}.jpg")

    # Build ffmpeg args: timeout must come before -i (input option)
    timeout_us = str(int(timeout * 1_000_000))
    args = [
        "ffmpeg",
        "-nostdin",                       # don't read from terminal
        "-loglevel", "error",
        "-rtsp_transport", "tcp",
        "-timeout", timeout_us,             # RTSP demuxer timeout in microseconds
        "-i", rtsp_url,
        "-vframes", "1",
        "-y",
        out_path,
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            _, stderr_data = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            await proc.wait()
            return None

        if proc.returncode != 0:
            err = stderr_data.decode(errors="replace").strip()[:120] if stderr_data else "unknown"
            print(f"  snapshot: ffmpeg failed: {err}", file=sys.stderr)
            if os.path.isfile(out_path):
                try:
                    os.remove(out_path)
                except OSError:
                    pass
            return None

        if os.path.isfile(out_path) and os.path.getsize(out_path) > 0:
            return out_path

        if os.path.isfile(out_path):
            try:
                os.remove(out_path)
            except OSError:
                pass
    except FileNotFoundError:
        return None
    except Exception as e:
        print(f"  snapshot: error: {e}", file=sys.stderr)
        return None

    return None
