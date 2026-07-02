#!/usr/bin/env python3
"""Run the peek RTSP scanner web interface directly."""

import sys
from peek.web_server import run_web_server

if __name__ == "__main__":
    port = 8000
    host = "127.0.0.1"
    
    if len(sys.argv) > 1:
        # Simple arg parsing for port
        try:
            port = int(sys.argv[1])
        except ValueError:
            print(f"Usage: python web.py [port] [host]")
            print(f"Defaulting port to {port}")
            
    if len(sys.argv) > 2:
        host = sys.argv[2]
        
    run_web_server(host=host, port=port)
