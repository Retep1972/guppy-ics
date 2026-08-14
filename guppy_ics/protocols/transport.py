from __future__ import annotations

from guppy_ics.core.addressing import classify_ip_address, communication_scope
from guppy_ics.protocols.base import ProtocolPlugin


class TransportPlugin(ProtocolPlugin):
    """
    Infrastructure plugin:
    Matches TCP/UDP traffic but does not register
    communications or assets.

    Exists only to ensure transport layers are
    observable for debugging / future use.
    """
    name = "Transport (TCP/UDP)"
    slug = "transport"
    safe_by_default = True

    def __init__(self):
        self.flows = {}

    def match(self, packet) -> bool:
        try:
            return (
                packet.haslayer("IP")
                and (packet.haslayer("TCP") or packet.haslayer("UDP"))
            )
        except Exception:
            return False

    def process(self, packet, state) -> None:
        try:
            ip = packet["IP"]
            layer_name = "TCP" if packet.haslayer("TCP") else "UDP"
            layer = packet[layer_name]
            protocol = layer_name.lower()
            src_ip = str(ip.src)
            dst_ip = str(ip.dst)
            src_port = int(layer.sport)
            dst_port = int(layer.dport)
            src_mac = str(getattr(packet, "src", "") or "")
            dst_mac = str(getattr(packet, "dst", "") or "")
            pkt_time = _packet_time(packet)

            if classify_ip_address(src_ip):
                state.register_special_address(src_ip)
            if classify_ip_address(dst_ip):
                state.register_special_address(dst_ip)

            key = (protocol, src_ip, src_port, dst_ip, dst_port)
            existing = self.flows.get(key)
            if not existing:
                existing = {
                    "transport_protocol": protocol,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "src_mac": src_mac or None,
                    "dst_mac": dst_mac or None,
                    "packet_count": 1,
                    "byte_count": len(bytes(packet)),
                    "first_seen": pkt_time,
                    "last_seen": pkt_time,
                    "scope": communication_scope(dst_ip, dst_mac),
                    "server_port": _server_port(protocol, src_port, dst_port),
                    "direction": "client_to_server" if _server_port(protocol, src_port, dst_port) == dst_port else "server_to_client",
                }
                self.flows[key] = existing
                evidence = state.register_evidence(
                    evidence_type=f"{protocol}_service_observation",
                    protocol=protocol,
                    source_asset=state.asset_index.get(src_ip),
                    destination_asset=state.asset_index.get(dst_ip),
                    attributes=existing,
                    timestamp=pkt_time,
                )
                if evidence:
                    existing["_evidence_ref"] = evidence["attributes"]
                return

            existing["packet_count"] += 1
            existing["byte_count"] += len(bytes(packet))
            existing["last_seen"] = pkt_time
            evidence_ref = existing.get("_evidence_ref")
            if evidence_ref is not None:
                evidence_ref["packet_count"] = existing["packet_count"]
                evidence_ref["byte_count"] = existing["byte_count"]
                evidence_ref["last_seen"] = existing["last_seen"]
        except Exception:
            return


def _packet_time(packet) -> str | None:
    try:
        return str(float(packet.time))
    except Exception:
        return None


def _server_port(protocol: str, src_port: int, dst_port: int) -> int:
    well_known_limit = 1024
    if dst_port < well_known_limit and src_port >= well_known_limit:
        return dst_port
    if src_port < well_known_limit and dst_port >= well_known_limit:
        return src_port
    return min(src_port, dst_port)
