"""Camera fingerprinting from RTSP Server header and SDP parsing."""

import re

FINGERPRINTS: list[tuple[str, list[str]]] = [
    ("Hikvision",  [r"hik", r"hikvision", r"ds-?\d", r"rtsp server\s*\("]),
    ("Dahua",      [r"dahua", r"\bipc\b", r"dh-"]),
    ("Axis",       [r"axis", r"vapix"]),
    ("Foscam",     [r"foscam"]),
    ("D-Link",     [r"d-?link", r"dcs-"]),
    ("Hanwha",     [r"hanwha", r"samsung", r"wisenet"]),
    ("Bosch",      [r"bosch"]),
    ("Ubiquiti",   [r"unifi", r"ubiquiti"]),
    ("Avigilon",   [r"avigilon"]),
    ("Vivotek",    [r"vivotek"]),
    ("Reolink",    [r"reolink"]),
    ("Amcrest",    [r"amcrest"]),
    ("TP-Link",    [r"tp-?link", r"tapo"]),
    ("Generic",    [r"rtsp", r"ipcam", r"ip camera"]),
]


def fingerprint(server: str) -> str:
    """Identify camera make from the RTSP Server header string."""
    if not server:
        return "Unknown"
    low = server.lower()
    for make, patterns in FINGERPRINTS:
        if any(re.search(p, low) for p in patterns):
            return make
    return "Unknown"


def parse_sdp(sdp: str) -> tuple[str, str]:
    """Extract video and audio codec names from an SDP body.

    Returns (video_codec, audio_codec). Either may be empty.
    """
    video = audio = ""
    current_media = None
    for line in sdp.splitlines():
        if line.startswith("m=video"):
            current_media = "video"
        elif line.startswith("m=audio"):
            current_media = "audio"
        elif line.startswith("a=rtpmap:") and current_media:
            try:
                codec = line.split(" ", 1)[1].split("/")[0]
            except IndexError:
                continue
            if current_media == "video" and not video:
                video = codec
            elif current_media == "audio" and not audio:
                audio = codec
    return video, audio


def extract_control_url(sdp: str, default_path: str) -> str:
    """Extract a=control URL from SDP body, falling back to default_path."""
    for line in sdp.splitlines():
        if line.startswith("a=control:"):
            ctrl = line.split(":", 1)[1].strip()
            if ctrl.startswith("rtsp://"):
                parts = ctrl.split("/", 3)
                return "/" + parts[3] if len(parts) > 3 else default_path
            return ctrl
    return default_path


def is_valid_sdp(sdp_body: str) -> bool:
    """True if body looks like valid SDP (starts with v=0)."""
    if not sdp_body:
        return False
    return "v=0" in sdp_body.splitlines()[:2]
