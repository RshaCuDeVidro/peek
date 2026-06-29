#!/usr/bin/env python3
"""peek — RTSP camera scanner with ONVIF, snapshots, and CIDR support.

Usage:
    python peek.py ips.txt
    python peek.py ips.txt -w 200 --snapshots
    python peek.py --target 192.168.1.0/24 --no-onvif
    python peek.py --asn AS28573 -w 200 --save open.txt
"""

from peek.cli import main

if __name__ == "__main__":
    main()
