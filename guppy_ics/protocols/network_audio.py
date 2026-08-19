from __future__ import annotations

import ipaddress
import re
from typing import Any

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

from guppy_ics.core.addressing import communication_scope
from guppy_ics.protocols.base import ProtocolPlugin


SIP_PORTS = {5060}
SIPS_PORTS = {5061}
PTP_PORTS = {319, 320}
RTP_MIN_PACKETS = 2
MAX_TRACKED_FLOWS = 2048
MAX_TRACKED_CALLS = 1024
SIP_METHODS = {
    "REGISTER",
    "INVITE",
    "ACK",
    "BYE",
    "CANCEL",
    "OPTIONS",
    "SUBSCRIBE",
    "NOTIFY",
    "MESSAGE",
    "INFO",
    "PRACK",
    "UPDATE",
    "REFER",
    "PUBLISH",
}
SAFE_SIP_HEADERS = {
    "from",
    "to",
    "contact",
    "via",
    "call-id",
    "cseq",
    "user-agent",
    "server",
    "allow",
    "supported",
    "require",
    "event",
    "subscription-state",
    "content-type",
    "content-length",
    "www-authenticate",
    "proxy-authenticate",
}
RTCP_TYPES = {
    200: "sender_report",
    201: "receiver_report",
    202: "source_description",
    203: "bye",
    204: "app",
}
PTP_MESSAGE_TYPES = {
    0x0: "sync",
    0x1: "delay_req",
    0x2: "pdelay_req",
    0x3: "pdelay_resp",
    0x8: "follow_up",
    0x9: "delay_resp",
    0xA: "pdelay_resp_follow_up",
    0xB: "announce",
    0xC: "signaling",
    0xD: "management",
}


class NetworkAudioPlugin(ProtocolPlugin):
    name = "SIP / RTP / network audio evidence"
    slug = "network_audio"
    safe_by_default = False
    ports = [5060, 5061, 319, 320]

    def __init__(self):
        self.rtp_flows: dict[tuple, dict[str, Any]] = {}
        self.rtcp_flows: dict[tuple, dict[str, Any]] = {}
        self.calls: dict[str, dict[str, Any]] = {}
        self.media_by_destination: dict[tuple, dict[str, Any]] = {}
        self.igmp_memberships: dict[tuple, dict[str, Any]] = {}

    def match(self, packet) -> bool:
        try:
            if not packet.haslayer(IP):
                return False
            if int(packet[IP].proto) == 2:
                return True
            if not (packet.haslayer(UDP) or packet.haslayer(TCP)):
                return False

            layer = packet[UDP] if packet.haslayer(UDP) else packet[TCP]
            ports = {int(layer.sport), int(layer.dport)}
            if ports & (SIP_PORTS | SIPS_PORTS | PTP_PORTS):
                return True

            raw = _raw_payload(packet)
            if raw and (_looks_like_sip(raw) or _looks_like_rtcp(raw) or _looks_like_rtp(raw)):
                return True
            return False
        except Exception:
            return False

    def process(self, packet, state) -> None:
        try:
            if int(packet[IP].proto) == 2:
                _process_igmp(packet, state, self.igmp_memberships)
                return

            layer = packet[UDP] if packet.haslayer(UDP) else packet[TCP]
            ports = {int(layer.sport), int(layer.dport)}
            raw = _raw_payload(packet)

            if ports & SIPS_PORTS and not raw:
                _process_sips_observation(packet, state)
                return

            if raw and _looks_like_sip(raw):
                self._process_sip(packet, state, raw)
                return

            if packet.haslayer(UDP) and (ports & PTP_PORTS or _looks_like_ptp(raw)):
                _process_ptp(packet, state, raw)
                return

            if packet.haslayer(UDP) and _looks_like_rtcp(raw):
                _process_rtcp(packet, state, raw, self.rtcp_flows)
                return

            if packet.haslayer(UDP) and _looks_like_rtp(raw):
                _process_rtp(packet, state, raw, self.rtp_flows, self.media_by_destination)
                return
        except Exception:
            return

    def _process_sip(self, packet, state, raw: bytes) -> None:
        parsed = parse_sip_message(raw)
        if not parsed:
            return

        ip = packet[IP]
        layer = packet[UDP] if packet.haslayer(UDP) else packet[TCP]
        src_asset = _link_l2_l3(packet, state, str(ip.src), "sip")
        dst_asset = _link_l2_l3(packet, state, str(ip.dst), "sip")

        if src_asset in state.assets:
            state.assets[src_asset]["protocols"].add("sip")
            _update_raw_identity(state.assets[src_asset], "sip", parsed)
        if dst_asset in state.assets:
            state.assets[dst_asset]["protocols"].add("sip")

        function = parsed.get("method") or f"response_{parsed.get('status_code')}"
        state.register_communication(
            src=str(ip.src),
            dst=str(ip.dst),
            protocol="sip",
            function=function,
            metadata={
                "src_port": int(layer.sport),
                "dst_port": int(layer.dport),
                "transport": "udp" if packet.haslayer(UDP) else "tcp",
                "call_id": parsed.get("call_id"),
                "request_uri": parsed.get("request_uri"),
                "status_code": parsed.get("status_code"),
            },
        )

        state.register_evidence(
            evidence_type="sip_message",
            protocol="sip",
            source_asset=src_asset,
            destination_asset=dst_asset,
            attributes=parsed,
            timestamp=_packet_time(packet),
        )

        _register_sip_behavior(packet, state, src_asset, dst_asset, parsed)
        self._process_sip_relationship(packet, state, parsed, src_asset, dst_asset)

        if parsed.get("sdp"):
            for media in parsed["sdp"].get("media", []):
                attrs = {
                    "signalling_protocol": "sip",
                    "call_id": parsed.get("call_id"),
                    "media_type": media.get("media_type"),
                    "destination_ip": media.get("connection_address") or parsed["sdp"].get("connection_address"),
                    "destination_port": media.get("port"),
                    "transport": media.get("transport"),
                    "payload_types": media.get("payload_types"),
                    "codecs": media.get("codecs"),
                    "scope": media.get("scope") or parsed["sdp"].get("scope"),
                    "direction": media.get("direction"),
                    "ptime": media.get("ptime"),
                    "rtcp": media.get("rtcp"),
                    "encrypted_media": _is_encrypted_media(media.get("transport")),
                }
                dest = attrs.get("destination_ip")
                port = attrs.get("destination_port")
                if dest:
                    state.register_special_address(str(dest))
                if dest and port:
                    self.media_by_destination[(str(dest), int(port))] = attrs
                state.register_evidence(
                    evidence_type="sdp_media",
                    protocol="sdp",
                    source_asset=src_asset,
                    destination_asset=dst_asset,
                    attributes=attrs,
                    timestamp=_packet_time(packet),
                )

    def _process_sip_relationship(self, packet, state, parsed: dict[str, Any], src_asset, dst_asset) -> None:
        method = parsed.get("method")
        if method == "REGISTER":
            attrs = {
                "endpoint_ip": packet[IP].src,
                "registrar_ip": packet[IP].dst,
                "sip_identity": parsed.get("to") or parsed.get("from"),
                "contact": parsed.get("contact"),
                "call_id": parsed.get("call_id"),
            }
            state.register_evidence(
                evidence_type="sip_registration",
                protocol="sip",
                source_asset=src_asset,
                destination_asset=dst_asset,
                attributes=attrs,
                timestamp=_packet_time(packet),
            )
            state.register_communication(src=packet[IP].src, dst=packet[IP].dst, protocol="sip", function="registers_to")
        elif method == "INVITE":
            attrs = {
                "caller_ip": packet[IP].src,
                "callee_ip": packet[IP].dst,
                "from": parsed.get("from"),
                "to": parsed.get("to"),
                "request_uri": parsed.get("request_uri"),
                "call_id": parsed.get("call_id"),
            }
            state.register_evidence(
                evidence_type="sip_session",
                protocol="sip",
                source_asset=src_asset,
                destination_asset=dst_asset,
                attributes=attrs,
                timestamp=_packet_time(packet),
            )
            state.register_communication(src=packet[IP].src, dst=packet[IP].dst, protocol="sip", function="sip_calls")


def parse_sip_message(raw: bytes) -> dict[str, Any] | None:
    text = raw[:16000].decode("utf-8", errors="ignore").replace("\r\n", "\n")
    if not text:
        return None
    header_text, _, body = text.partition("\n\n")
    lines = header_text.split("\n")[:80]
    if not lines:
        return None
    start = lines[0].strip()[:300]
    parsed: dict[str, Any] = {"start_line": start}
    method = None
    status_code = None
    if start.upper().startswith("SIP/2.0"):
        parts = start.split(" ", 2)
        if len(parts) >= 2 and parts[1].isdigit():
            status_code = int(parts[1])
            parsed["status_code"] = status_code
            parsed["reason_phrase"] = parts[2][:120] if len(parts) > 2 else ""
        else:
            return None
    else:
        parts = start.split()
        if len(parts) < 3 or parts[0].upper() not in SIP_METHODS or "SIP/2.0" not in parts[-1].upper():
            return None
        method = parts[0].upper()
        parsed["method"] = method
        parsed["request_uri"] = _bounded(parts[1], 300)
        parsed["request_uri_user"], parsed["request_uri_host"] = _parse_sip_uri(parts[1])

    headers = _parse_headers(lines[1:])
    for key in SAFE_SIP_HEADERS:
        value = headers.get(key)
        if not value:
            continue
        if key in {"www-authenticate", "proxy-authenticate"}:
            realm = _auth_realm(value)
            if realm:
                parsed[f"{key.replace('-', '_')}_realm"] = realm
            continue
        parsed[key.replace("-", "_")] = _bounded(value, 500)

    if headers.get("authorization"):
        realm = _auth_realm(headers["authorization"])
        if realm:
            parsed["authorization_realm"] = realm

    cseq = headers.get("cseq", "")
    if cseq:
        parsed["cseq_method"] = cseq.split()[-1].upper()[:40]
    call_id = headers.get("call-id")
    if call_id:
        parsed["call_id"] = _bounded(call_id, 200)
    for uri_field in ("from", "to", "contact"):
        if parsed.get(uri_field):
            user, host = _parse_sip_uri(str(parsed[uri_field]))
            if user:
                parsed[f"{uri_field}_user"] = user
            if host:
                parsed[f"{uri_field}_host"] = host

    if "application/sdp" in headers.get("content-type", "").lower():
        parsed["sdp"] = parse_sdp(body)
    return parsed


def parse_sdp(body: str) -> dict[str, Any]:
    lines = [line.strip() for line in body.replace("\r\n", "\n").split("\n") if len(line.strip()) >= 2][:200]
    session: dict[str, Any] = {"media": []}
    current_media: dict[str, Any] | None = None
    session_connection = None
    for line in lines:
        prefix, value = line[0], line[2:] if len(line) > 2 and line[1] == "=" else ""
        if not value:
            continue
        if prefix in {"v", "o", "s", "t"}:
            session[prefix] = _bounded(value, 300)
        elif prefix == "c":
            conn = _parse_sdp_connection(value)
            if current_media is not None:
                current_media.update(conn)
            else:
                session.update(conn)
                session_connection = conn
        elif prefix == "m":
            parts = value.split()
            if len(parts) >= 4:
                current_media = {
                    "media_type": parts[0],
                    "port": _int_or_none(parts[1]),
                    "transport": parts[2],
                    "payload_types": [_int_or_string(p) for p in parts[3:20]],
                    "codecs": [],
                }
                if session_connection:
                    current_media.update(session_connection)
                session["media"].append(current_media)
        elif prefix == "a" and current_media is not None:
            _apply_sdp_attribute(current_media, value)
    return session


def _process_rtp(packet, state, raw: bytes, flows: dict, media_by_destination: dict) -> None:
    header = _parse_rtp(raw)
    if not header:
        return
    ip = packet[IP]
    udp = packet[UDP]
    dst_ip = str(ip.dst)
    src_ip = str(ip.src)
    dst_mac = str(getattr(packet, "dst", "") or "")
    key = (src_ip, int(udp.sport), dst_ip, int(udp.dport), header["ssrc"])
    entry = flows.get(key)
    pkt_time = _packet_time(packet)
    if entry is None:
        if len(flows) >= MAX_TRACKED_FLOWS:
            return
        entry = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": int(udp.sport),
            "dst_port": int(udp.dport),
            "ssrc": header["ssrc"],
            "payload_types": {header["payload_type"]},
            "sequence_min": header["sequence_number"],
            "sequence_max": header["sequence_number"],
            "timestamp_min": header["timestamp"],
            "timestamp_max": header["timestamp"],
            "packet_count": 1,
            "byte_count": len(raw),
            "first_seen": pkt_time,
            "last_seen": pkt_time,
            "scope": communication_scope(dst_ip, dst_mac),
            "matched_sdp": media_by_destination.get((dst_ip, int(udp.dport))),
        }
        flows[key] = entry
        return

    entry["packet_count"] += 1
    entry["byte_count"] += len(raw)
    entry["last_seen"] = pkt_time
    entry["payload_types"].add(header["payload_type"])
    entry["sequence_min"] = min(entry["sequence_min"], header["sequence_number"])
    entry["sequence_max"] = max(entry["sequence_max"], header["sequence_number"])
    entry["timestamp_min"] = min(entry["timestamp_min"], header["timestamp"])
    entry["timestamp_max"] = max(entry["timestamp_max"], header["timestamp"])

    if entry["packet_count"] < RTP_MIN_PACKETS:
        return

    src_asset = _link_l2_l3(packet, state, src_ip, "rtp")
    dst_asset = state.asset_index.get(dst_ip)
    attrs = _plain_rtp_entry(entry)
    state.register_special_address(dst_ip)
    if entry["scope"] != "multicast":
        dst_asset = _link_l2_l3(packet, state, dst_ip, "rtp")
        state.register_communication(src=src_ip, dst=dst_ip, protocol="rtp", function="sends_rtp", metadata=attrs)
    else:
        state.register_communication(src=src_ip, dst=src_ip, protocol="rtp", function=f"sends_rtp_to {dst_ip}:{int(udp.dport)}", metadata=attrs)

    evidence = entry.get("_evidence_ref")
    if evidence is None:
        record = state.register_evidence(
            evidence_type="rtp_stream",
            protocol="rtp",
            source_asset=src_asset,
            destination_asset=dst_asset,
            attributes=attrs,
            timestamp=entry["first_seen"],
        )
        if record:
            entry["_evidence_ref"] = record["attributes"]
    else:
        evidence.update(attrs)
    if entry.get("matched_sdp"):
        state.register_evidence(
            evidence_type="multicast_media_group" if entry["scope"] == "multicast" else "media_stream_correlation",
            protocol="rtp",
            source_asset=src_asset,
            attributes={
                "group": dst_ip if entry["scope"] == "multicast" else None,
                "port": int(udp.dport),
                "media_protocol": "rtp",
                "source_ip": src_ip,
                "matched_sdp": entry["matched_sdp"],
            },
            timestamp=pkt_time,
        )


def _process_rtcp(packet, state, raw: bytes, flows: dict) -> None:
    parsed = _parse_rtcp(raw)
    if not parsed:
        return
    ip = packet[IP]
    udp = packet[UDP]
    src_asset = _link_l2_l3(packet, state, str(ip.src), "rtcp")
    state.register_special_address(str(ip.dst))
    attrs = {
        "src_ip": str(ip.src),
        "dst_ip": str(ip.dst),
        "src_port": int(udp.sport),
        "dst_port": int(udp.dport),
        **parsed,
        "scope": communication_scope(str(ip.dst), getattr(packet, "dst", None)),
    }
    state.register_evidence(
        evidence_type="rtcp_stream",
        protocol="rtcp",
        source_asset=src_asset,
        attributes=attrs,
        timestamp=_packet_time(packet),
    )


def _process_igmp(packet, state, memberships: dict) -> None:
    ip = packet[IP]
    raw = bytes(ip.payload)
    if len(raw) < 8:
        return
    igmp_type = raw[0]
    group = ".".join(str(part) for part in raw[4:8])
    event = {
        0x11: "membership_query",
        0x12: "membership_report",
        0x16: "membership_report",
        0x17: "leave_group",
        0x22: "membership_report_v3",
    }.get(igmp_type, f"type_{igmp_type:02x}")
    version = "v3" if igmp_type == 0x22 else "v2" if igmp_type in {0x16, 0x17} else "v1_or_v2"
    src_asset = _link_l2_l3(packet, state, str(ip.src), "igmp")
    if group != "0.0.0.0":
        state.register_special_address(group)
    attrs = {
        "src_ip": str(ip.src),
        "group": group,
        "event": event,
        "igmp_version": version,
    }
    state.register_evidence(
        evidence_type="igmp_membership",
        protocol="igmp",
        source_asset=src_asset,
        attributes=attrs,
        timestamp=_packet_time(packet),
    )
    if event in {"membership_report", "membership_report_v3"} and group != "0.0.0.0":
        state.register_communication(src=str(ip.src), dst=str(ip.src), protocol="igmp", function=f"joins_multicast {group}")
    elif event == "leave_group" and group != "0.0.0.0":
        state.register_communication(src=str(ip.src), dst=str(ip.src), protocol="igmp", function=f"leaves_multicast {group}")


def _process_ptp(packet, state, raw: bytes) -> None:
    if len(raw) < 34:
        return
    ip = packet[IP]
    src_asset = _link_l2_l3(packet, state, str(ip.src), "ptp")
    message_type = raw[0] & 0x0F
    attrs = {
        "src_ip": str(ip.src),
        "dst_ip": str(ip.dst),
        "ptp_version": raw[1] & 0x0F,
        "message_type": PTP_MESSAGE_TYPES.get(message_type, f"type_{message_type}"),
        "domain_number": raw[4],
        "sequence_id": int.from_bytes(raw[30:32], "big"),
        "clock_identity": raw[20:28].hex(":"),
        "source_port_id": int.from_bytes(raw[28:30], "big"),
    }
    state.register_special_address(str(ip.dst))
    state.register_evidence(
        evidence_type="ptp_observation",
        protocol="ptp",
        source_asset=src_asset,
        attributes=attrs,
        timestamp=_packet_time(packet),
    )


def _process_sips_observation(packet, state) -> None:
    ip = packet[IP]
    layer = packet[TCP] if packet.haslayer(TCP) else packet[UDP]
    src_asset = _link_l2_l3(packet, state, str(ip.src), "sips")
    dst_asset = _link_l2_l3(packet, state, str(ip.dst), "sips")
    state.register_communication(
        src=str(ip.src),
        dst=str(ip.dst),
        protocol="sips",
        function="encrypted_signalling",
        metadata={"src_port": int(layer.sport), "dst_port": int(layer.dport)},
    )
    state.register_evidence(
        evidence_type="sip_tls_observation",
        protocol="sips",
        source_asset=src_asset,
        destination_asset=dst_asset,
        attributes={"src_ip": str(ip.src), "dst_ip": str(ip.dst), "encrypted": True},
        timestamp=_packet_time(packet),
    )


def _register_sip_behavior(packet, state, src_asset, dst_asset, parsed):
    attrs = {
        "methods_sent": [parsed["method"]] if parsed.get("method") else [],
        "methods_received": [parsed["method"]] if parsed.get("method") else [],
        "response_codes": [parsed["status_code"]] if parsed.get("status_code") else [],
        "user_agents": [parsed["user_agent"]] if parsed.get("user_agent") else [],
        "servers": [parsed["server"]] if parsed.get("server") else [],
        "event": parsed.get("event"),
    }
    state.register_evidence(
        evidence_type="sip_behavior",
        protocol="sip",
        source_asset=src_asset,
        destination_asset=dst_asset,
        attributes=attrs,
        timestamp=_packet_time(packet),
    )


def _update_raw_identity(asset, protocol: str, parsed: dict[str, Any]) -> None:
    fields = asset.setdefault("metadata", {}).setdefault("raw_protocol_identity", {}).setdefault(protocol, {})
    for key in ("user_agent", "server", "from", "to", "contact", "authorization_realm", "www_authenticate_realm"):
        if parsed.get(key):
            fields[key] = parsed[key]


def _link_l2_l3(packet, state, ip_value: str, protocol: str):
    if hasattr(packet, "src") and str(getattr(packet, "src", "") or "").count(":") == 5 and packet[IP].src == ip_value:
        return state.link_identifiers(str(packet.src), ip_value, protocol=protocol, reason="l2_l3_observed")
    if hasattr(packet, "dst") and str(getattr(packet, "dst", "") or "").count(":") == 5 and packet[IP].dst == ip_value:
        return state.link_identifiers(str(packet.dst), ip_value, protocol=protocol, reason="l2_l3_observed")
    return state.register_asset(ip_value, protocol=protocol, evidence_layer="l3")


def _looks_like_sip(raw: bytes) -> bool:
    text = raw[:40].decode("ascii", errors="ignore").upper()
    if text.startswith("SIP/2.0 "):
        return True
    return any(text.startswith(method + " ") and "SIP/2.0" in text for method in SIP_METHODS)


def _looks_like_rtp(raw: bytes) -> bool:
    return _parse_rtp(raw) is not None


def _looks_like_rtcp(raw: bytes) -> bool:
    return _parse_rtcp(raw) is not None


def _looks_like_ptp(raw: bytes) -> bool:
    return len(raw) >= 34 and (raw[0] & 0x0F) in PTP_MESSAGE_TYPES and (raw[1] & 0x0F) in {1, 2}


def _parse_rtp(raw: bytes) -> dict[str, int] | None:
    if len(raw) < 12:
        return None
    first = raw[0]
    version = first >> 6
    if version != 2:
        return None
    cc = first & 0x0F
    header_len = 12 + cc * 4
    if len(raw) < header_len:
        return None
    payload_type = raw[1] & 0x7F
    if payload_type in {72, 73}:
        return None
    return {
        "payload_type": payload_type,
        "sequence_number": int.from_bytes(raw[2:4], "big"),
        "timestamp": int.from_bytes(raw[4:8], "big"),
        "ssrc": int.from_bytes(raw[8:12], "big"),
    }


def _parse_rtcp(raw: bytes) -> dict[str, Any] | None:
    if len(raw) < 8 or raw[0] >> 6 != 2:
        return None
    packet_type = raw[1]
    if packet_type not in RTCP_TYPES:
        return None
    return {
        "packet_type": RTCP_TYPES[packet_type],
        "report_count": raw[0] & 0x1F,
        "ssrc": int.from_bytes(raw[4:8], "big"),
    }


def _plain_rtp_entry(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "src_ip": entry["src_ip"],
        "dst_ip": entry["dst_ip"],
        "src_port": entry["src_port"],
        "dst_port": entry["dst_port"],
        "ssrc": entry["ssrc"],
        "payload_types": sorted(entry["payload_types"]),
        "sequence_min": entry["sequence_min"],
        "sequence_max": entry["sequence_max"],
        "timestamp_min": entry["timestamp_min"],
        "timestamp_max": entry["timestamp_max"],
        "packet_count": entry["packet_count"],
        "byte_count": entry["byte_count"],
        "first_seen": entry["first_seen"],
        "last_seen": entry["last_seen"],
        "scope": entry["scope"],
        "matched_sdp": entry.get("matched_sdp"),
    }


def _parse_headers(lines: list[str]) -> dict[str, str]:
    headers = {}
    current = None
    for line in lines[:80]:
        if not line:
            continue
        if line[0] in " \t" and current:
            headers[current] = _bounded(headers[current] + " " + line.strip(), 1000)
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        current = key.strip().lower()
        headers[current] = _bounded(value.strip(), 1000)
    return headers


def _parse_sip_uri(value: str) -> tuple[str | None, str | None]:
    match = re.search(r"sips?:([^@>\s;]+)@([^;>\s]+)", value, flags=re.IGNORECASE)
    if not match:
        return None, None
    return _bounded(match.group(1), 120), _bounded(match.group(2), 200)


def _auth_realm(value: str) -> str | None:
    match = re.search(r'realm\s*=\s*"([^"]{1,200})"', value, flags=re.IGNORECASE)
    if match:
        return match.group(1)
    return None


def _parse_sdp_connection(value: str) -> dict[str, Any]:
    parts = value.split()
    if len(parts) < 3:
        return {}
    address = parts[2].split("/")[0]
    return {
        "address_family": parts[1],
        "connection_address": address,
        "scope": "multicast" if _is_multicast(address) else "unicast",
    }


def _apply_sdp_attribute(media: dict[str, Any], value: str) -> None:
    if value.startswith("rtpmap:"):
        payload, _, rest = value[7:].partition(" ")
        codec_parts = rest.split("/")
        codec = {
            "payload_type": _int_or_string(payload),
            "name": codec_parts[0] if codec_parts else None,
            "clock_rate": _int_or_none(codec_parts[1]) if len(codec_parts) > 1 else None,
            "channels": _int_or_none(codec_parts[2]) if len(codec_parts) > 2 else None,
        }
        media.setdefault("codecs", []).append(codec)
    elif value.startswith("fmtp:"):
        media.setdefault("fmtp", []).append(_bounded(value[5:], 300))
    elif value in {"sendonly", "recvonly", "sendrecv", "inactive"}:
        media["direction"] = value
    elif value.startswith("ptime:"):
        media["ptime"] = _int_or_none(value[6:])
    elif value.startswith("maxptime:"):
        media["maxptime"] = _int_or_none(value[9:])
    elif value.startswith("rtcp:"):
        media["rtcp"] = _bounded(value[5:], 120)


def _is_multicast(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_multicast
    except ValueError:
        return False


def _is_encrypted_media(transport: str | None) -> bool:
    return bool(transport and "SAVP" in transport.upper())


def _raw_payload(packet) -> bytes:
    return bytes(packet[Raw].load) if packet.haslayer(Raw) else b""


def _int_or_none(value) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _int_or_string(value):
    parsed = _int_or_none(value)
    return parsed if parsed is not None else str(value)


def _bounded(value, limit: int) -> str:
    return str(value)[:limit]


def _packet_time(packet) -> str | None:
    try:
        return str(float(packet.time))
    except Exception:
        return None
