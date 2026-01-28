from __future__ import annotations
from guppy_ics.protocols.base import ProtocolPlugin
from scapy.layers.inet import IP, TCP


class TCPPlugin(ProtocolPlugin):
    name = "tcp"
    slug = "tcp"
    safe_by_default = True

    def __init__(self):
        self.seen_flows = set()

    def match(self, packet) -> bool:
        try:
            return packet.haslayer("IP") and packet.haslayer("TCP")
        except Exception:
            return False

    def process(self, pkt, state):
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return

        src = pkt[IP].src
        dst = pkt[IP].dst
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport

        # Direction-independent flow key (critical for live mode)
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
            protocol="tcp",
            metadata={
                "src_port": sport,
                "dst_port": dport,
            },
        )
