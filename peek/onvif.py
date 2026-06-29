"""Async ONVIF SOAP client — minimal DeviceInformation query.

Probes common ONVIF ports (80, 8899, 8082) with a GetDeviceInformation
SOAP request. Extracts manufacturer, model, firmware, serial, hardware ID.
"""

import asyncio
import re

from peek.models import OnvifInfo

ONVIF_PORTS = (80, 8899, 8082)
ONVIF_TIMEOUT = 3.0

_GET_DEVICE_INFO_SOAP = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
    '<s:Body>'
    '<GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl"/>'
    '</s:Body>'
    '</s:Envelope>'
)

_ONVIF_PATH = "/onvif/device_service"

_RESP_RE = re.compile(
    r"<(?:tds:)?(Manufacturer|Model|FirmwareVersion|SerialNumber|HardwareId)>"
    r"(.*?)</(?:tds:)?(Manufacturer|Model|FirmwareVersion|SerialNumber|HardwareId)>",
    re.DOTALL,
)

_FIELD_MAP = {
    "Manufacturer": "manufacturer",
    "Model": "model",
    "FirmwareVersion": "firmware_version",
    "SerialNumber": "serial_number",
    "HardwareId": "hardware_id",
}


async def probe_onvif(ip: str, timeout: float = ONVIF_TIMEOUT) -> OnvifInfo | None:
    """Try GetDeviceInformation on common ONVIF ports. Returns info or None."""
    request = (
        f"POST {_ONVIF_PATH} HTTP/1.1\r\n"
        f"Host: {ip}\r\n"
        f"Content-Type: application/soap+xml; charset=utf-8\r\n"
        f"Content-Length: {len(_GET_DEVICE_INFO_SOAP)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
        f"{_GET_DEVICE_INFO_SOAP}"
    ).encode()

    for port in ONVIF_PORTS:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )
        except (asyncio.TimeoutError, OSError):
            continue

        try:
            writer.write(request)
            await writer.drain()

            response = b""
            while True:
                try:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
                    if not chunk:
                        break
                    response += chunk
                except asyncio.TimeoutError:
                    break

            text = response.decode(errors="replace")
            if "GetDeviceInformationResponse" not in text:
                continue

            info = _parse_device_info(text)
            if info and info.manufacturer:
                return info
        except Exception:
            continue
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    return None


def _parse_device_info(xml_text: str) -> OnvifInfo | None:
    fields: dict[str, str] = {}
    for m in _RESP_RE.finditer(xml_text):
        tag = m.group(1) or m.group(3)
        value = (m.group(2) or "").strip()
        key = _FIELD_MAP.get(tag, "")
        if key and value:
            fields[key] = value
    if fields:
        return OnvifInfo(**fields)  # type: ignore[arg-type]
    return None
