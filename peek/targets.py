"""Parse target specifications: IP, CIDR, ranges, Feistel sampling, and port-per-target syntax."""

import hashlib
import ipaddress
import math
import re
import socket
import struct
import subprocess
import sys

# ── Feistel cipher for pseudorandom IP sampling ─────────────────────────────

class Feistel32:
    """32-bit Feistel network — deterministic permutation of [0, 2^bits).

    Encrypting 0, 1, 2, ..., N produces a pseudorandom sequence with no
    duplicates, without materializing the entire range.  Used for uniform
    sampling from large CIDR blocks.
    """

    def __init__(self, key: bytes, bits: int = 32, rounds: int = 8):
        if bits % 2 != 0:
            raise ValueError("bits must be even")
        self.bits = bits
        self.half = bits // 2
        self.mask = (1 << bits) - 1
        self.half_mask = (1 << self.half) - 1
        self.rounds = rounds
        self._subkeys = self._expand_key(key)

    def _expand_key(self, key: bytes) -> list[bytes]:
        """Derive per-round subkeys from master key."""
        subkeys = []
        for i in range(self.rounds):
            subkeys.append(hashlib.sha256(key + struct.pack(">I", i)).digest())
        return subkeys

    def _round_fn(self, rhs: int, subkey: bytes) -> int:
        """Round function F(right_half, subkey) → left_half-sized output."""
        data = struct.pack(">I", rhs) + subkey
        h = hashlib.sha256(data).digest()
        # Take enough bytes to cover half_bits
        val = int.from_bytes(h[:4], "big")
        return val & self.half_mask

    def encrypt(self, n: int) -> int:
        """Encrypt integer n (0 <= n < 2^bits). Bijection."""
        if n < 0 or n > self.mask:
            raise ValueError(f"n out of range [0, {self.mask}]")
        left = (n >> self.half) & self.half_mask
        right = n & self.half_mask
        for i in range(self.rounds):
            f = self._round_fn(right, self._subkeys[i])
            new_right = left ^ f
            left = right
            right = new_right
        return (left << self.half) | right


def _sample_cidr(net: ipaddress.IPv4Network, n: int, key: bytes | None = None) -> list[str]:
    """Sample n pseudorandom IPs from a CIDR block using Feistel cycle-walking.

    Deterministic — same key + CIDR + n always returns the same IPs.
    """
    if key is None:
        key = str(net).encode()
    hosts = list(net.hosts())
    size = len(hosts)
    base = int(hosts[0])

    if n >= size:
        return [str(h) for h in hosts]

    # Find smallest power of 2 >= size for the Feistel domain
    bits = max(2, math.ceil(math.log2(size)))
    if bits % 2 != 0:
        bits += 1

    feistel = Feistel32(key, bits=bits)
    domain = 1 << bits
    ips: list[str] = []
    seen: set[int] = set()

    for i in range(domain):
        if len(ips) >= n:
            break
        candidate = feistel.encrypt(i)
        if candidate < size and candidate not in seen:
            seen.add(candidate)
            ips.append(str(ipaddress.IPv4Address(base + candidate)))

    return ips


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


def expand_target(raw: str, default_port: int = 554,
                   sample_size: int | None = None) -> list[tuple[str, int]]:
    """Expand a single target spec into (ip, port) pairs.

    Supported formats:
        - 192.168.1.1
        - 192.168.1.1:8554
        - 192.168.1.0/24
        - 10.0.0.1-10.0.0.50
        - 10.0.0.1-50

    If *sample_size* is set and a CIDR block has more hosts than that,
    sample pseudorandomly via Feistel cycle-walking instead of expanding
    all hosts (deterministic — same inputs always pick the same IPs).
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

        # IPv6 not supported — skip silently
        if isinstance(net, ipaddress.IPv6Network):
            print(f"Warning: skipping {raw} (IPv6 not supported)", file=sys.stderr)
            return []

        n_hosts = net.num_addresses - 2  # exclude network + broadcast

        if sample_size and n_hosts > sample_size:
            print(f"Sampling {sample_size:,} IPs from {raw} "
                  f"({n_hosts:,} hosts, prefix /{net.prefixlen})", file=sys.stderr)
            ips = _sample_cidr(net, sample_size)
            return [(ip, port) for ip in ips]

        if n_hosts > 65534 and net.prefixlen < 16:
            print(f"Warning: skipping {raw} ({n_hosts:,} IPs, too large). "
                  f"Use --sample N to sample, or --max-cidr {net.prefixlen} to allow.",
                  file=sys.stderr)
            return []
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
                  default_port: int = 554,
                  sample_size: int | None = None) -> list[tuple[str, int]]:
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
        for ip, port in expand_target(spec, default_port, sample_size):
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
    output = ""
    # Try using pure Python socket first (zero dependencies)
    try:
        with socket.create_connection((server, 43), timeout=10.0) as s:
            s.sendall(f"AS{asn_num}\r\n".encode("utf-8"))
            chunks = []
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            output = b"".join(chunks).decode("utf-8", errors="ignore")
    except Exception:
        # Fallback to subprocess whois command if socket connection fails
        try:
            result = subprocess.run(
                ["whois", "-h", server, f"AS{asn_num}"],
                capture_output=True, text=True, timeout=15,
            )
            output = result.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
            return []

    prefixes: list[str] = []
    for line in output.splitlines():
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


