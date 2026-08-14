from __future__ import annotations

import re

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP

from guppy_ics.core.addressing import communication_scope
from guppy_ics.protocols.base import ProtocolPlugin
from guppy_ics.protocols.mac_helper import is_valid_mac


DHCP_PORTS = {67, 68}
DNS_PORTS = {53}
MDNS_PORTS = {5353}
LLMNR_PORTS = {5355}
NETBIOS_PORTS = {137, 138}
SSDP_PORTS = {1900}
WS_DISCOVERY_PORTS = {3702}


class DiscoveryEvidencePlugin(ProtocolPlugin):
    name = "Discovery evidence"
    slug = "discovery"
    safe_by_default = False

    def match(self, packet) -> bool:
        try:
            if not packet.haslayer(IP) or not packet.haslayer(UDP):
                return False
            udp = packet[UDP]
            ports = {int(udp.sport), int(udp.dport)}
            return bool(
                ports
                & (
                    DHCP_PORTS
                    | DNS_PORTS
                    | MDNS_PORTS
                    | LLMNR_PORTS
                    | NETBIOS_PORTS
                    | SSDP_PORTS
                    | WS_DISCOVERY_PORTS
                )
            )
        except Exception:
            return False

    def process(self, packet, state) -> None:
        try:
            udp = packet[UDP]
            ports = {int(udp.sport), int(udp.dport)}
            if ports & DHCP_PORTS:
                _process_dhcp(packet, state)
            if ports & (DNS_PORTS | MDNS_PORTS | LLMNR_PORTS):
                _process_dns_like(packet, state)
            if ports & NETBIOS_PORTS:
                _process_netbios(packet, state)
            if ports & SSDP_PORTS:
                _process_ssdp(packet, state)
            if ports & WS_DISCOVERY_PORTS:
                _process_ws_discovery(packet, state)
        except Exception:
            return


def _process_dhcp(packet, state) -> None:
    if not packet.haslayer(BOOTP) or not packet.haslayer(DHCP):
        return

    bootp = packet[BOOTP]
    options = _dhcp_options(packet[DHCP].options)
    mac = _bootp_mac(bootp)
    requested_ip = options.get("requested_addr")
    yiaddr = str(getattr(bootp, "yiaddr", "") or "")
    ciaddr = str(getattr(bootp, "ciaddr", "") or "")

    asset_id = None
    if mac and is_valid_mac(mac):
        asset_id = state.register_asset(mac, protocol="dhcp", evidence_layer="l2")
        for ip_value, reason in ((yiaddr, "dhcp_yiaddr"), (requested_ip, "dhcp_requested_ip"), (ciaddr, "dhcp_ciaddr")):
            if ip_value and ip_value != "0.0.0.0":
                asset_id = state.link_identifiers(mac, str(ip_value), protocol="dhcp", reason=reason)

    hostname = _first_option(options, "hostname", "fqdn")
    if hostname and asset_id and asset_id in state.assets:
        state.assets[asset_id]["identifiers"].setdefault("hostname", set()).add(str(hostname))
        state.assets[asset_id]["metadata"].setdefault("raw_protocol_identity", {}).setdefault("dhcp", {})["hostname"] = str(hostname)

    attrs = {
        "client_mac": mac,
        "ciaddr": ciaddr,
        "yiaddr": yiaddr,
        "requested_ip": requested_ip,
        "server_identifier": options.get("server_id"),
        "hostname": hostname,
        "fqdn": options.get("fqdn"),
        "vendor_class": options.get("vendor_class_id"),
        "client_identifier": options.get("client_id"),
        "parameter_request_list": options.get("param_req_list"),
        "message_type": options.get("message-type"),
        "relay_agent_information": options.get("relay_agent_information"),
    }
    state.register_evidence(
        evidence_type="dhcp",
        protocol="dhcp",
        source_asset=asset_id,
        attributes=attrs,
        timestamp=_packet_time(packet),
    )


def _process_dns_like(packet, state) -> None:
    if not packet.haslayer(DNS):
        return
    dns = packet[DNS]
    udp = packet[UDP]
    protocol = "dns"
    if udp.sport in LLMNR_PORTS or udp.dport in LLMNR_PORTS:
        protocol = "llmnr"
    elif udp.sport in MDNS_PORTS or udp.dport in MDNS_PORTS:
        protocol = "mdns"

    src_asset = state.asset_index.get(packet[IP].src)
    if src_asset:
        state.assets[src_asset]["protocols"].add(protocol)

    attrs = {
        "src_ip": packet[IP].src,
        "dst_ip": packet[IP].dst,
        "src_port": int(udp.sport),
        "dst_port": int(udp.dport),
        "scope": communication_scope(packet[IP].dst, getattr(packet, "dst", None)),
        "queries": _dns_records(dns, "qd", query=True),
        "answers": _dns_records(dns, "an"),
    }
    state.register_evidence(
        evidence_type=protocol,
        protocol=protocol,
        source_asset=src_asset,
        attributes=attrs,
        timestamp=_packet_time(packet),
    )


def _process_netbios(packet, state) -> None:
    udp = packet[UDP]
    src_asset = state.asset_index.get(packet[IP].src)
    if src_asset:
        state.assets[src_asset]["protocols"].add("netbios")

    attrs = {
        "src_ip": packet[IP].src,
        "dst_ip": packet[IP].dst,
        "src_port": int(udp.sport),
        "dst_port": int(udp.dport),
        "scope": communication_scope(packet[IP].dst, getattr(packet, "dst", None)),
        "message_type": "name_service" if 137 in {int(udp.sport), int(udp.dport)} else "datagram",
    }
    if packet.haslayer(DNS):
        attrs["names"] = _dns_records(packet[DNS], "qd", query=True)
    state.register_evidence(
        evidence_type="netbios",
        protocol="netbios",
        source_asset=src_asset,
        attributes=attrs,
        timestamp=_packet_time(packet),
    )


def _process_ssdp(packet, state) -> None:
    payload = _raw_payload(packet)
    if not payload:
        return
    headers = _headers(payload)
    first_line = payload.splitlines()[0].decode("iso-8859-1", errors="ignore") if payload.splitlines() else ""
    src_asset = state.asset_index.get(packet[IP].src)
    if src_asset:
        state.assets[src_asset]["protocols"].add("ssdp")
    state.register_evidence(
        evidence_type="ssdp",
        protocol="ssdp",
        source_asset=src_asset,
        attributes={
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "method": first_line.split(" ", 1)[0] if first_line else None,
            "host": headers.get("host"),
            "st": headers.get("st"),
            "nt": headers.get("nt"),
            "nts": headers.get("nts"),
            "usn": headers.get("usn"),
            "server": headers.get("server"),
            "location": headers.get("location"),
            "cache_control": headers.get("cache-control"),
            "scope": communication_scope(packet[IP].dst, getattr(packet, "dst", None)),
        },
        timestamp=_packet_time(packet),
    )


def _process_ws_discovery(packet, state) -> None:
    payload = _raw_payload(packet)
    if not payload:
        return
    text = payload[:12000].decode("utf-8", errors="ignore")
    src_asset = state.asset_index.get(packet[IP].src)
    if src_asset:
        state.assets[src_asset]["protocols"].add("ws_discovery")
    state.register_evidence(
        evidence_type="ws_discovery",
        protocol="ws_discovery",
        source_asset=src_asset,
        attributes={
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "types": _xml_values(text, "Types"),
            "scopes": _xml_values(text, "Scopes"),
            "endpoint_address": _xml_values(text, "Address"),
            "xaddrs": _xml_values(text, "XAddrs"),
            "metadata_version": _xml_values(text, "MetadataVersion"),
            "message_id": _xml_values(text, "MessageID"),
            "relates_to": _xml_values(text, "RelatesTo"),
            "scope": communication_scope(packet[IP].dst, getattr(packet, "dst", None)),
        },
        timestamp=_packet_time(packet),
    )


def _dhcp_options(options) -> dict:
    parsed = {}
    for opt in options:
        if not isinstance(opt, tuple) or not opt:
            continue
        name = str(opt[0])
        value = opt[1] if len(opt) > 1 else None
        parsed[name] = _decode_value(value)
    return parsed


def _bootp_mac(bootp) -> str | None:
    try:
        raw = bytes(bootp.chaddr)[: int(bootp.hlen)]
        if len(raw) < 6:
            return None
        return ":".join(f"{b:02x}" for b in raw[:6])
    except Exception:
        return None


def _dns_records(dns, field: str, *, query: bool = False) -> list[dict]:
    records = []
    for current in _packet_list(getattr(dns, field, None))[:25]:
        records.append(
            {
                "name": _decode_value(getattr(current, "qname", None) if query else getattr(current, "rrname", None)),
                "type": _decode_value(getattr(current, "qtype", None) if query else getattr(current, "type", None)),
                "rdata": _decode_value(getattr(current, "rdata", None)) if not query else None,
            }
        )
    return records


def _packet_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return [item for item in value if item]
    if isinstance(value, tuple):
        return [item for item in value if item]
    if hasattr(value, "__iter__") and not isinstance(value, (bytes, str)):
        try:
            return [item for item in value if item]
        except TypeError:
            pass
    return [value]


def _headers(payload: bytes) -> dict:
    result = {}
    text = payload[:8000].decode("iso-8859-1", errors="ignore")
    for line in text.splitlines()[1:80]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        result[key.strip().lower()] = value.strip()
    return result


def _xml_values(text: str, local_name: str) -> list[str]:
    values = []
    for match in re.finditer(
        rf"<(?:[A-Za-z0-9_]+:)?{re.escape(local_name)}(?:\s[^>]*)?>\s*(.*?)\s*</(?:[A-Za-z0-9_]+:)?{re.escape(local_name)}>",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    ):
        value = re.sub(r"\s+", " ", match.group(1)).strip()
        if value:
            values.append(value)
    return values[:25]


def _raw_payload(packet) -> bytes:
    if packet.haslayer("Raw"):
        return bytes(packet["Raw"].load)
    return b""


def _decode_value(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore").rstrip(".")
    if isinstance(value, (list, tuple)):
        return [_decode_value(v) for v in value[:50]]
    return value


def _first_option(options: dict, *names: str):
    for name in names:
        value = options.get(name)
        if value:
            return value
    return None


def _packet_time(packet) -> str | None:
    try:
        return str(float(packet.time))
    except Exception:
        return None
