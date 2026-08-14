from __future__ import annotations

import re

from guppy_ics.protocols.base import ProtocolPlugin


HTTP_PORTS = {80, 8080, 8000, 8008, 8081, 8888}


class HTTPPlugin(ProtocolPlugin):
    name = "HTTP"
    slug = "http"
    safe_by_default = True
    ports = sorted(HTTP_PORTS)

    def __init__(self):
        self.seen_flows = set()

    def match(self, packet) -> bool:
        try:
            if not packet.haslayer("IP") or not packet.haslayer("TCP"):
                return False
            payload = _raw_payload(packet)
            if not payload:
                return False
            tcp = packet["TCP"]
            ports = {int(tcp.sport), int(tcp.dport)}
            return bool(ports & HTTP_PORTS) and _is_http(payload)
        except Exception:
            return False

    def process(self, packet, state) -> None:
        try:
            ip = packet["IP"]
            tcp = packet["TCP"]
            src_ip = ip.src
            dst_ip = ip.dst
            src_port = int(tcp.sport)
            dst_port = int(tcp.dport)
            payload = _raw_payload(packet)

            is_response = payload.upper().startswith(b"HTTP/")
            server_ip = src_ip if is_response or src_port in HTTP_PORTS else dst_ip
            client_ip = dst_ip if server_ip == src_ip else src_ip

            server_metadata = _server_metadata(payload) if is_response else None
            client_metadata = _client_metadata(payload) if not is_response else None

            state.register_asset(
                server_ip,
                role="http_server",
                protocol=self.slug,
                metadata=server_metadata,
                evidence_layer="l3",
            )
            state.register_asset(
                client_ip,
                role="http_client",
                protocol=self.slug,
                metadata=client_metadata,
                evidence_layer="l3",
            )

            flow = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)]))
            if flow in self.seen_flows:
                return
            self.seen_flows.add(flow)

            metadata = {
                "src_port": src_port,
                "dst_port": dst_port,
                "transport": "tcp",
            }
            path = _request_path(payload)
            if path:
                metadata["request_uri"] = path
            server_asset_id = state.asset_index.get(server_ip)
            if server_asset_id:
                metadata["server_asset_id"] = server_asset_id

            state.register_communication(
                src=src_ip,
                dst=dst_ip,
                protocol=self.slug,
                function="response" if is_response else "request",
                metadata=metadata,
            )
        except Exception:
            return


def _raw_payload(packet) -> bytes:
    if packet.haslayer("Raw"):
        return bytes(packet["Raw"].load)
    return b""


def _is_http(payload: bytes) -> bool:
    upper = payload[:32].upper()
    return (
        upper.startswith(b"GET ")
        or upper.startswith(b"POST ")
        or upper.startswith(b"HEAD ")
        or upper.startswith(b"PUT ")
        or upper.startswith(b"DELETE ")
        or upper.startswith(b"OPTIONS ")
        or upper.startswith(b"HTTP/")
    )


def _headers(payload: bytes) -> dict:
    text = payload.decode("iso-8859-1", errors="ignore")
    header_text = text.split("\r\n\r\n", 1)[0]
    out = {}
    for line in header_text.splitlines()[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        out[key.strip().lower()] = value.strip()
    return out


def _server_metadata(payload: bytes) -> dict | None:
    headers = _headers(payload)
    fields = {}
    if headers.get("server"):
        fields["server"] = headers["server"]
    if headers.get("www-authenticate"):
        fields["www_authenticate"] = headers["www-authenticate"]
    if headers.get("location"):
        fields["location"] = headers["location"]
    title = _html_title(payload)
    if title:
        fields["title"] = title
    if not fields:
        return None
    return {"raw_protocol_identity": {"http": fields}}


def _client_metadata(payload: bytes) -> dict | None:
    headers = _headers(payload)
    user_agent = headers.get("user-agent")
    if not user_agent:
        return None
    return {"raw_protocol_identity": {"http": {"user_agent": user_agent}}}


def _html_title(payload: bytes) -> str | None:
    text = payload.decode("iso-8859-1", errors="ignore")
    match = re.search(r"<title>\s*(.*?)\s*</title>", text, flags=re.IGNORECASE | re.DOTALL)
    if not match:
        return None
    return re.sub(r"\s+", " ", match.group(1)).strip() or None


def _request_path(payload: bytes) -> str | None:
    try:
        first_line = payload.splitlines()[0].decode("ascii", errors="ignore")
    except Exception:
        return None
    parts = first_line.split()
    if len(parts) >= 2:
        return parts[1]
    return None
