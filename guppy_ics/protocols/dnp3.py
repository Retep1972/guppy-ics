from __future__ import annotations

from guppy_ics.protocols.base import ProtocolPlugin


DNP3_UDP_PORT = 20000


class DNP3Plugin(ProtocolPlugin):
    name = "DNP3"
    slug = "dnp3"
    safe_by_default = False
    ports = [DNP3_UDP_PORT]

    def match(self, packet) -> bool:
        try:
            return (
                packet.haslayer("IP")
                and packet.haslayer("UDP")
                and (
                    packet["UDP"].sport == DNP3_UDP_PORT
                    or packet["UDP"].dport == DNP3_UDP_PORT
                )
            )
        except Exception:
            return False

    def process(self, packet, state) -> None:
        try:
            ip = packet["IP"]
            udp = packet["UDP"]

            src_ip = ip.src
            dst_ip = ip.dst

            # ----------------------------
            # Link L2 <-> L3 identities
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
            # Role inference
            # ----------------------------
            if udp.dport == DNP3_UDP_PORT:
                client_ip = src_ip
                server_ip = dst_ip
                direction = "request"
            else:
                client_ip = dst_ip
                server_ip = src_ip
                direction = "response"

            metadata = {
                "src_port": int(udp.sport),
                "dst_port": int(udp.dport),
                "transport": "udp",
            }

            # ----------------------------
            # Register assets (L3 evidence)
            # ----------------------------
            state.register_asset(
                server_ip,
                role="dnp3_outstation",
                protocol=self.slug,
                evidence_layer="l3",
            )

            state.register_asset(
                client_ip,
                role="dnp3_master",
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
                metadata=metadata,
            )

        except Exception:
            return
