from __future__ import annotations

from guppy_ics.protocols.base import ProtocolPlugin


OPCUA_PORTS = {4840, 4843}
OPCUA_TCP_MESSAGE_TYPES = {b"HEL", b"ACK", b"ERR", b"OPN", b"CLO", b"MSG"}
OPCUA_CHUNK_TYPES = {ord("F"), ord("C"), ord("A")}


class OPCUAPlugin(ProtocolPlugin):
    name = "OPC UA"
    slug = "opcua"
    safe_by_default = False
    ports = list(OPCUA_PORTS)

    def match(self, packet) -> bool:
        try:
            if not packet.haslayer("IP") or not packet.haslayer("TCP"):
                return False

            if packet["TCP"].sport in OPCUA_PORTS or packet["TCP"].dport in OPCUA_PORTS:
                return True

            return _looks_like_opcua_tcp_payload(packet)
        except Exception:
            return False

    def process(self, packet, state) -> None:
        try:
            # Must be IP + TCP
            if not packet.haslayer("IP") or not packet.haslayer("TCP"):
                return

            ip = packet["IP"]
            tcp = packet["TCP"]
            message_type = _opcua_message_type(packet)

            src_ip = ip.src
            dst_ip = ip.dst

            # ----------------------------
            # Link L2 <-> L3 identities
            # (observational only)
            # ----------------------------
            if hasattr(packet, "src") and ":" in str(packet.src):
                state.link_identifiers(
                    packet.src,
                    src_ip,
                    protocol=self.slug,
                    reason="l2_l3_observed",
                )

            if hasattr(packet, "dst") and ":" in str(packet.dst):
                state.link_identifiers(
                    packet.dst,
                    dst_ip,
                    protocol=self.slug,
                    reason="l2_l3_observed",
                )

            # ----------------------------
            # Client / Server roles
            # ----------------------------
            if tcp.dport in OPCUA_PORTS:
                client_ip = src_ip
                server_ip = dst_ip
                direction = "request"
            elif tcp.sport in OPCUA_PORTS:
                client_ip = dst_ip
                server_ip = src_ip
                direction = "response"
            else:
                client_ip, server_ip, direction = _infer_client_server(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    sport=int(tcp.sport),
                    dport=int(tcp.dport),
                    message_type=message_type,
                )

            # ----------------------------
            # Register assets (L3 evidence)
            # ----------------------------
            state.register_asset(
                server_ip,
                role="opcua_server",
                protocol=self.slug,
                evidence_layer="l3",
            )

            state.register_asset(
                client_ip,
                role="opcua_client",
                protocol=self.slug,
                evidence_layer="l3",
            )

            # ----------------------------
            # Register communication
            # ----------------------------
            state.register_communication(
                src=src_ip,
                dst=dst_ip,
                protocol=self.slug,
                function=direction,
                metadata={
                    "src_port": int(tcp.sport),
                    "dst_port": int(tcp.dport),
                    "server_port": int(tcp.dport if server_ip == dst_ip else tcp.sport),
                    "message_type": message_type,
                },
            )

        except Exception:
            # Never break analysis on malformed packets
            return


def _looks_like_opcua_tcp_payload(packet) -> bool:
    message_type = _opcua_message_type(packet)
    return message_type is not None


def _opcua_message_type(packet) -> str | None:
    if not packet.haslayer("Raw"):
        return None

    raw = bytes(packet["Raw"].load)
    if len(raw) < 8:
        return None

    message_type = raw[0:3]
    chunk_type = raw[3]
    message_size = int.from_bytes(raw[4:8], "little")
    if message_type not in OPCUA_TCP_MESSAGE_TYPES:
        return None
    if chunk_type not in OPCUA_CHUNK_TYPES:
        return None
    if message_size < 8:
        return None

    return message_type.decode("ascii")


def _infer_client_server(
    *,
    src_ip: str,
    dst_ip: str,
    sport: int,
    dport: int,
    message_type: str | None,
) -> tuple[str, str, str]:
    if message_type == "HEL":
        return src_ip, dst_ip, "request"
    if message_type in {"ACK", "ERR"}:
        return dst_ip, src_ip, "response"

    if sport >= 49152 and dport < 49152:
        return src_ip, dst_ip, "request"
    if dport >= 49152 and sport < 49152:
        return dst_ip, src_ip, "response"

    if message_type == "CLO":
        return src_ip, dst_ip, "request"

    return src_ip, dst_ip, "observed"
