"""ONVIF WS-Discovery client using UDP multicast to discover local network cameras."""

import socket
import uuid
import re

def discover_local_cameras(timeout=1.5):
    """Sends a WS-Discovery UDP multicast probe and collects response IP addresses.
    
    Returns:
        List of unique IP strings discovered on the local network.
    """
    message_id = f"uuid:{uuid.uuid4()}"
    soap_probe = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
          '<Header>'
            f'<wsa:MessageID xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">{message_id}</wsa:MessageID>'
            '<wsa:To xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">urn:schemas-xmlsoap-org:ws:2004:08:discovery</wsa:To>'
            '<wsa:Action xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">http://schemas.xmlsoap.org/ws/2004/08/discovery/Probe</wsa:Action>'
          '</Header>'
          '<Body>'
            '<Probe xmlns="http://schemas.xmlsoap.org/ws/2004/08/discovery">'
              '<Types>dn:NetworkVideoTransmitter</Types>'
            '</Probe>'
          '</Body>'
        '</Envelope>'
    )

    multicast_group = "239.255.255.250"
    port = 3702
    discovered_ips = set()

    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(timeout)

    # Set TTL for multicast packets (usually 1 or 2 is enough for local network)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

    try:
        # Send SOAP probe
        sock.sendto(soap_probe.encode("utf-8"), (multicast_group, port))
        
        # Listen for replies
        start_time = socket.getdefaulttimeout()
        while True:
            try:
                data, addr = sock.recvfrom(65535)
                ip = addr[0]
                
                # Double-check if the response looks like an ONVIF/WS-Discovery XML
                resp_text = data.decode("utf-8", errors="ignore")
                if "ProbeMatches" in resp_text or message_id in resp_text:
                    discovered_ips.add(ip)
                else:
                    # Generic response check
                    if "schemas-xmlsoap-org" in resp_text or "onvif" in resp_text:
                        discovered_ips.add(ip)
            except socket.timeout:
                break
            except Exception:
                break
    except Exception as e:
        print(f"[DISCOVERY ERROR] {e}")
    finally:
        sock.close()

    return sorted(list(discovered_ips))
