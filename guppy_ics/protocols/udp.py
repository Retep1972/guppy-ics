from __future__ import annotations
from guppy_ics.protocols.base import ProtocolPlugin
from scapy.layers.inet import IP, UDP


class UDPPlugin(ProtocolPlugin):
    name = "udp"
    slug = "udp"
    safe_by_default = True

    def __init__(self):
        self.seen_flows = set()
    
    def match(self, packet) -> bool:
        try:
            return packet.haslayer("IP") and packet.haslayer("UDP")
        except Exception:
            return False

    def process(self, pkt, state):
        if not pkt.haslayer(IP) or not pkt.haslayer(UDP):
            return

        src = pkt[IP].src
        dst = pkt[IP].dst
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport

        # Direction-independent flow key
        flow = tuple(sorted([
            (src, sport),
            (dst, dport),
        ]))

        if flow in self.seen_flows:
            return

        self.seen_flows.add(flow)

        state.register_communication(
            src=src,
            dst=dst,
            protocol="udp",
            metadata={
                "src_port": sport,
                "dst_port": dport,
            },
        )
