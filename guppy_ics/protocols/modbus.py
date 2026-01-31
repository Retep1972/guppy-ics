from __future__ import annotations

from guppy_ics.protocols.base import ProtocolPlugin


class ModbusPlugin(ProtocolPlugin):
    name = "Modbus TCP"
    slug = "modbus"
    safe_by_default = False
    ports = [502]

    def match(self, packet) -> bool:
        try:
            if not packet.haslayer("TCP"):
                return False

            tcp = packet["TCP"]
            return tcp.sport == 502 or tcp.dport == 502
        except Exception:
            return False

    def process(self, packet, state) -> None:
        try:
            # Modbus TCP must be IP + TCP
            if not packet.haslayer("IP") or not packet.haslayer("TCP"):
                return

            ip = packet["IP"]
            tcp = packet["TCP"]

            src_ip = ip.src
            dst_ip = ip.dst

            # ----------------------------
            # Link L2 <-> L3 identities
            # (does NOT imply L3 visibility)
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
            if tcp.dport == 502:
                client_ip = src_ip
                server_ip = dst_ip
                direction = "request"
            else:
                client_ip = dst_ip
                server_ip = src_ip
                direction = "response"

            # ----------------------------
            # Register assets (L3 evidence)
            # ----------------------------
            state.register_asset(
                client_ip,
                role="client",
                protocol=self.slug,
                evidence_layer="l3",
            )

            state.register_asset(
                server_ip,
                role="plc",
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
                },
            )

        except Exception:
            # Never break analysis on malformed packets
            return
