from __future__ import annotations
from guppy_ics.protocols.base import ProtocolPlugin


class L2L3LinkerPlugin(ProtocolPlugin):
    """
    Infrastructure plugin:
    Links MAC <-> IP for ANY Ethernet+IP packet.
    """
    name = "L2/L3 Identity Linker"
    slug = "l2l3"
    safe_by_default = True

    def match(self, packet) -> bool:
        try:
            return packet.haslayer("IP") and hasattr(packet, "src") and hasattr(packet, "dst")
        except Exception:
            return False

    def process(self, packet, state) -> None:
        try:
            ip = packet["IP"]

            src_mac = packet.src
            dst_mac = packet.dst
            src_ip = ip.src
            dst_ip = ip.dst

            if src_mac and src_ip:
                state.link_identifiers(
                    src_mac,
                    src_ip,
                    protocol=self.slug,
                    reason="l2_l3_observed",
                )

            if dst_mac and dst_ip:
                state.link_identifiers(
                    dst_mac,
                    dst_ip,
                    protocol=self.slug,
                    reason="l2_l3_observed",
                )

            state.register_communication(
                src=src_ip,
                dst=dst_ip,
                protocol="ip",
                function="l3",
            )

        except Exception:
            return

