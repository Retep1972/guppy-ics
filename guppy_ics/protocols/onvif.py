from __future__ import annotations

import re

from guppy_ics.protocols.base import ProtocolPlugin


ONVIF_HTTP_PORTS = {80, 8080, 8000, 8899}
RTSP_PORTS = {554, 8554}
WS_DISCOVERY_PORT = 3702


class ONVIFPlugin(ProtocolPlugin):
    name = "ONVIF / RTSP Camera"
    slug = "onvif"
    safe_by_default = True
    ports = sorted(ONVIF_HTTP_PORTS | RTSP_PORTS | {WS_DISCOVERY_PORT})

    def __init__(self):
        self.seen_flows = set()

    def match(self, packet) -> bool:
        try:
            if not packet.haslayer("IP"):
                return False

            payload = _raw_payload(packet)

            if packet.haslayer("UDP"):
                udp = packet["UDP"]
                if udp.sport == WS_DISCOVERY_PORT or udp.dport == WS_DISCOVERY_PORT:
                    return _payload_mentions_onvif(payload)

            if not packet.haslayer("TCP"):
                return False

            tcp = packet["TCP"]
            ports = {int(tcp.sport), int(tcp.dport)}

            if ports & ONVIF_HTTP_PORTS and _payload_mentions_onvif(payload):
                return True

            if ports & RTSP_PORTS:
                return True

            return _payload_is_rtsp(payload)
        except Exception:
            return False

    def process(self, packet, state) -> None:
        try:
            ip = packet["IP"]
            src_ip = ip.src
            dst_ip = ip.dst

            src_port = None
            dst_port = None
            transport = None
            function = "onvif"

            if packet.haslayer("TCP"):
                tcp = packet["TCP"]
                src_port = int(tcp.sport)
                dst_port = int(tcp.dport)
                transport = "tcp"
                function = _tcp_function(packet)
                camera_ip, client_ip = _camera_client_from_ports(
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                )
            elif packet.haslayer("UDP"):
                udp = packet["UDP"]
                src_port = int(udp.sport)
                dst_port = int(udp.dport)
                transport = "udp"
                function = "ws_discovery"
                camera_ip, client_ip = dst_ip, src_ip
            else:
                return

            state.register_asset(
                camera_ip,
                role="camera",
                protocol=self.slug,
                metadata=_asset_metadata_from_payload(_raw_payload(packet)),
                evidence_layer="l3",
            )
            state.register_asset(
                client_ip,
                role="video_client",
                protocol=self.slug,
                evidence_layer="l3",
            )

            flow = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)]))
            if flow in self.seen_flows:
                return
            self.seen_flows.add(flow)

            metadata = {
                "src_port": src_port,
                "dst_port": dst_port,
                "transport": transport,
            }
            if function in {"rtsp_control", "rtsp_media"}:
                metadata["media_type"] = "video"
            path = _http_or_rtsp_path(_raw_payload(packet))
            if path:
                metadata["service_path"] = path
                if function in {"rtsp_control", "rtsp_media"}:
                    metadata["request_uri"] = path
            rtsp_server = _rtsp_server(_raw_payload(packet))
            if rtsp_server:
                metadata["server"] = rtsp_server
            session = _header_value(_raw_payload(packet), "session")
            if session:
                metadata["session"] = session
            user_agent = _header_value(_raw_payload(packet), "user-agent")
            if user_agent:
                metadata["user_agent"] = user_agent
            camera_asset_id = state.asset_index.get(camera_ip)
            if camera_asset_id:
                metadata["server_asset_id"] = camera_asset_id

            state.register_communication(
                src=src_ip,
                dst=dst_ip,
                protocol=self.slug,
                function=function,
                metadata=metadata,
            )
        except Exception:
            return


def _raw_payload(packet) -> bytes:
    if packet.haslayer("Raw"):
        return bytes(packet["Raw"].load)
    return b""


def _payload_mentions_onvif(payload: bytes) -> bool:
    lower = payload.lower()
    return (
        b"/onvif" in lower
        or b"onvif.org" in lower
        or b"www.onvif.org" in lower
        or b"tds:getdeviceinformation" in lower
        or b"trt:getprofiles" in lower
    )


def _payload_is_rtsp(payload: bytes) -> bool:
    upper = payload.upper()
    return (
        upper.startswith(b"OPTIONS ")
        or upper.startswith(b"DESCRIBE ")
        or upper.startswith(b"SETUP ")
        or upper.startswith(b"PLAY ")
        or upper.startswith(b"TEARDOWN ")
        or upper.startswith(b"RTSP/")
        or b" RTSP/1." in upper
    )


def _tcp_function(packet) -> str:
    payload = _raw_payload(packet)
    if _payload_mentions_onvif(payload):
        return "onvif_http"
    if _payload_is_rtsp(payload):
        return "rtsp_control"
    return "rtsp_media"


def _camera_client_from_ports(src_ip: str, dst_ip: str, src_port: int, dst_port: int):
    if src_port in RTSP_PORTS or src_port in ONVIF_HTTP_PORTS:
        return src_ip, dst_ip
    return dst_ip, src_ip


def _http_or_rtsp_path(payload: bytes) -> str | None:
    if not payload:
        return None
    try:
        first_line = payload.splitlines()[0].decode("ascii", errors="ignore")
    except Exception:
        return None

    parts = first_line.split()
    if len(parts) >= 2 and (
        parts[0].upper() in {"GET", "POST", "OPTIONS", "DESCRIBE", "SETUP", "PLAY"}
    ):
        return parts[1]
    return None


def _asset_metadata_from_payload(payload: bytes) -> dict | None:
    identity = _onvif_device_information(payload)
    if not identity:
        return None
    return {
        "raw_protocol_identity": {
            "onvif": identity,
        }
    }


def _onvif_device_information(payload: bytes) -> dict:
    if not payload:
        return {}

    text = payload.decode("utf-8", errors="ignore")
    fields = {
        "Manufacturer": ("manufacturer", "manufacturer_name"),
        "Model": ("model",),
        "FirmwareVersion": ("firmware_version", "software_version"),
        "SerialNumber": ("serial_number",),
        "HardwareId": ("hardware_id",),
    }
    identity = {}
    for xml_name, aliases in fields.items():
        value = _xml_value(text, xml_name)
        if value:
            for alias in aliases:
                identity[alias] = value
    return identity


def _xml_value(text: str, local_name: str) -> str | None:
    match = re.search(
        rf"<(?:[A-Za-z0-9_]+:)?{re.escape(local_name)}>\s*(.*?)\s*</(?:[A-Za-z0-9_]+:)?{re.escape(local_name)}>",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )
    if not match:
        return None
    value = re.sub(r"\s+", " ", match.group(1)).strip()
    return value or None


def _rtsp_server(payload: bytes) -> str | None:
    return _header_value(payload, "server")


def _header_value(payload: bytes, header_name: str) -> str | None:
    if not payload:
        return None
    text = payload.decode("iso-8859-1", errors="ignore")
    prefix = f"{header_name.lower()}:"
    for line in text.splitlines():
        if line.lower().startswith(prefix):
            value = line.split(":", 1)[1].strip()
            return value or None
    return None
