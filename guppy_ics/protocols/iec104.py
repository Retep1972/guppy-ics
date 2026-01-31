from __future__ import annotations

from guppy_ics.protocols.base import ProtocolPlugin


class IEC104Plugin(ProtocolPlugin):
    name = "IEC 60870-5-104"
    slug = "iec104"
    safe_by_default = False
    ports = [2404]

    def match(self, packet) -> bool:
        try:
            return (
                packet.haslayer("IP")
                and packet.haslayer("TCP")
                and (
                    packet["TCP"].sport == 2404
                    or packet["TCP"].dport == 2404
                )
            )
        except Exception:
            return False

    def process(self, packet, state) -> None:
        try:
            # Must be IP + TCP
            if not packet.haslayer("IP") or not packet.haslayer("TCP"):
                return

            ip = packet["IP"]
            tcp = packet["TCP"]

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
            if tcp.dport == 2404:
                client_ip = src_ip
                server_ip = dst_ip
                function = "request"
            else:
                client_ip = dst_ip
                server_ip = src_ip
                function = "response"

            # ----------------------------
            # Register assets (L3 evidence)
            # ----------------------------
            state.register_asset(
                server_ip,
                role="iec104_server",
                protocol=self.slug,
                evidence_layer="l3",
            )

            state.register_asset(
                client_ip,
                role="iec104_client",
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
                function=function,
                metadata={
                    "src_port": int(tcp.sport),
                    "dst_port": int(tcp.dport),
                },
            )

        except Exception:
            # Never break analysis on malformed packets
            return
