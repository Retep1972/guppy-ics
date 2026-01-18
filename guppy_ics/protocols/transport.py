from __future__ import annotations
from guppy_ics.protocols.base import ProtocolPlugin


class TransportPlugin(ProtocolPlugin):
    name = "Transport (TCP/UDP)"
    slug = "transport"
    safe_by_default = True

    def match(self, packet) -> bool:
        try:
            return packet.haslayer("IP") and (packet.haslayer("TCP") or packet.haslayer("UDP"))
        except Exception:
            return False

    def process(self, packet, state) -> None:
        try:
            ip = packet["IP"]
            src_ip = ip.src
            dst_ip = ip.dst

            if packet.haslayer("TCP"):
                l4 = packet["TCP"]
                proto = "tcp"
            else:
                l4 = packet["UDP"]
                proto = "udp"

            state.register_communication(
                src=src_ip,
                dst=dst_ip,
                protocol=proto,
                function="L4",
                metadata={
                    "src_port": int(l4.sport),
                    "dst_port": int(l4.dport),
                },
            )
        except Exception:
            return
