from __future__ import annotations
from guppy_ics.protocols.base import ProtocolPlugin


class S7CommPlugin(ProtocolPlugin):
    name = "S7comm / ISO-on-TCP"
    slug = "s7comm"
    safe_by_default = True
    ports = [102]

    def match(self, packet) -> bool:
        try:
            return (
                packet.haslayer("IP")
                and packet.haslayer("TCP")
                and (packet["TCP"].sport == 102 or packet["TCP"].dport == 102)
            )
        except Exception:
            return False

    def process(self, packet, state) -> None:
        try:
            ip = packet["IP"]
            tcp = packet["TCP"]

            src_ip = ip.src
            dst_ip = ip.dst

            # Role heuristic
            if tcp.dport == 102:
                client = src_ip
                plc = dst_ip
                direction = "request"
            else:
                client = dst_ip
                plc = src_ip
                direction = "response"

            state.register_asset(plc, role="plc", protocol=self.slug)
            state.register_asset(client, role="engineering_station", protocol=self.slug)

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
            return
