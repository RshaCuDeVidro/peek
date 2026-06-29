"""Parse target specifications: IP, CIDR, ranges, and port-per-target syntax."""

import ipaddress
import re
import subprocess
import sys

# Matches: 192.168.1.1-192.168.1.50 or 10.0.0.1-50
_RANGE_RE = re.compile(
    r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*-\s*"
    r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\d{1,3})$"
)


def _expand_range(spec: str) -> list[str]:
    """Expand a range like '10.0.0.1-10.0.0.50' or '10.0.0.1-50' into individual IPs."""
    m = _RANGE_RE.fullmatch(spec)
    if not m:
        return [spec]
    start_ip = m.group(1)
    end_spec = m.group(2)
    start_parts = [int(x) for x in start_ip.split(".")]
    if "." in end_spec:
        end_parts = [int(x) for x in end_spec.split(".")]
    else:
        end_parts = start_parts[:3] + [int(end_spec)]
    start_int = (start_parts[0] << 24 | start_parts[1] << 16 |
                 start_parts[2] << 8 | start_parts[3])
    end_int = (end_parts[0] << 24 | end_parts[1] << 16 |
               end_parts[2] << 8 | end_parts[3])
    if start_int > end_int:
        start_int, end_int = end_int, start_int
    ips = []
    for ip_int in range(start_int, end_int + 1):
        ips.append(
            f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}."
            f"{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}"
        )
    return ips


def expand_target(raw: str, default_port: int = 554) -> list[tuple[str, int]]:
    """Expand a single target spec into (ip, port) pairs.

    Supported formats:
        - 192.168.1.1
        - 192.168.1.1:8554
        - 192.168.1.0/24
        - 10.0.0.1-10.0.0.50
        - 10.0.0.1-50
    """
    raw = raw.split("#")[0].strip()
    if not raw:
        return []

    port = default_port
    port_match = re.search(r":(\d{1,5})$", raw)
    if port_match:
        port = int(port_match.group(1))
        raw = raw[:port_match.start()]

    # CIDR
    try:
        net = ipaddress.ip_network(raw, strict=False)
        return [(str(host), port) for host in net.hosts()]
    except ValueError:
        pass

    # Range
    m = _RANGE_RE.fullmatch(raw)
    if m:
        return [(ip, port) for ip in _expand_range(raw)]

    # Single IP
    return [(raw, port)]


def parse_targets(input_path: str | None = None,
                  extra: list[str] | None = None,
                  default_port: int = 554) -> list[tuple[str, int]]:
    """Parse targets from file and/or CLI args. Deduplicates."""
    raw_specs: list[str] = []

    if input_path:
        try:
            with open(input_path) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        raw_specs.append(line)
        except FileNotFoundError:
            print(f"Error: File '{input_path}' not found", file=sys.stderr)
            sys.exit(1)

    if extra:
        raw_specs.extend(extra)

    if not raw_specs:
        print("Error: No targets provided", file=sys.stderr)
        sys.exit(1)

    seen: set[tuple[str, int]] = set()
    targets: list[tuple[str, int]] = []
    for spec in raw_specs:
        for ip, port in expand_target(spec, default_port):
            key = (ip, port)
            if key not in seen:
                seen.add(key)
                targets.append(key)

    return targets


def read_lines(filepath: str) -> list[str]:
    """Read non-empty, non-comment lines from a file."""
    out: list[str] = []
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            out.append(line)
    return out


def read_creds(filepath: str) -> list[tuple[str, str]]:
    """Read credentials file (user:password per line)."""
    creds: list[tuple[str, str]] = []
    for line in read_lines(filepath):
        if ":" in line:
            u, p = line.split(":", 1)
            creds.append((u.strip(), p.strip()))
        else:
            creds.append((line.strip(), ""))
    return creds


_WHOIS_SERVERS = [
    ("whois.lacnic.net", ["inetnum:", "route:"]),   # LACNIC (Latin America)
    ("whois.radb.net",   ["route:"]),                # RADB (global mirror)
    ("whois.ripe.net",   ["route:", "inetnum:"]),    # RIPE (Europe)
    ("whois.arin.net",   ["route:"]),                # ARIN (North America)
    ("whois.apnic.net",  ["route:", "inetnum:"]),    # APNIC (Asia-Pacific)
]


def _try_whois_server(server: str, asn_num: str, keys: list[str]) -> list[str]:
    """Query a whois server for an ASN, return list of prefix strings."""
    try:
        result = subprocess.run(
            ["whois", "-h", server, f"AS{asn_num}"],
            capture_output=True, text=True, timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        return []

    prefixes: list[str] = []
    for line in result.stdout.splitlines():
        line_lower = line.lower().strip()
        for key in keys:
            if line_lower.startswith(key):
                pfx = line.split(":", 1)[1].strip()
                if pfx:
                    prefixes.append(pfx)
                break
    return prefixes


def expand_asn(asn: str) -> list[str]:
    """Fetch route prefixes for an ASN via whois (multiple region servers).

    Returns list of CIDR strings. Empty list if whois unavailable or not found.
    """
    asn_num = str(asn).upper().replace("AS", "").strip()
    if not asn_num.isdigit():
        print(f"Error: Invalid ASN '{asn}'", file=sys.stderr)
        return []

    # Try servers in order until we get results
    for server, keys in _WHOIS_SERVERS:
        prefixes = _try_whois_server(server, asn_num, keys)
        if prefixes:
            return prefixes

    return []


