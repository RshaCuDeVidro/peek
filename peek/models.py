"""Data models for RTSP Checker."""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class OnvifInfo:
    """ONVIF device information extracted via SOAP."""
    manufacturer: str = ""
    model: str = ""
    firmware_version: str = ""
    serial_number: str = ""
    hardware_id: str = ""


@dataclass
class PathResult:
    path: str
    status: str  # OPEN, OPEN_AUTH, AUTH, CLOSED, ERROR, OTHER
    status_code: int = 0
    server: str = ""
    credential: str = ""
    sdp_video: str = ""
    sdp_audio: str = ""
    details: str = ""
    transport: str = ""  # "tcp" or "udp"


@dataclass
class CameraResult:
    ip: str
    port: int = 554
    results: list = field(default_factory=list)
    make: str = "Unknown"
    onvif: Optional[OnvifInfo] = None
    snapshot_path: str = ""

    @property
    def open_result(self) -> Optional[PathResult]:
        opens = [r for r in self.results if r.status in ("OPEN", "OPEN_AUTH")]
        return opens[0] if opens else None

    @property
    def is_open(self) -> bool:
        return self.open_result is not None

    @property
    def best_result(self) -> Optional[PathResult]:
        if self.open_result:
            return self.open_result
        auths = [r for r in self.results if r.status == "AUTH"]
        if auths:
            return auths[0]
        closeds = [r for r in self.results if r.status == "CLOSED"]
        if closeds:
            return closeds[0]
        return self.results[0] if self.results else None

    @property
    def summary_status(self) -> str:
        b = self.best_result
        if not b:
            return "NO_RESPONSE"
        if b.status == "OPEN":
            return "OPEN"
        if b.status == "OPEN_AUTH":
            return "OPEN(AUTH)"
        if b.status == "AUTH":
            return "AUTH"
        if b.status == "CLOSED":
            return "CLOSED"
        if b.status == "ERROR":
            return "ERROR"
        return f"HTTP{b.status_code}"

    @property
    def rtsp_url(self) -> str:
        b = self.best_result
        if not b:
            return f"rtsp://{self.ip}:{self.port}/"
        return f"rtsp://{self.ip}:{self.port}{b.path}"

    @property
    def rtsp_url_with_auth(self) -> str:
        b = self.best_result
        if not b:
            return self.rtsp_url
        if b.credential and ":" in b.credential:
            u, _, pw = b.credential.partition(":")
            return f"rtsp://{u}:{pw}@{self.ip}:{self.port}{b.path}"
        return self.rtsp_url


@dataclass
class ScanConfig:
    """Configuration for a scan run."""
    targets: list = field(default_factory=list)  # list of (ip, port)
    paths: list = field(default_factory=list)
    creds: list = field(default_factory=list)  # list of (user, password)
    workers: int = 50
    timeout: float = 5.0
    onvif: bool = True
    snapshot: bool = False
    snapshot_dir: str = "snapshots"
