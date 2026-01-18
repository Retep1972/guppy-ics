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
            ip = packet["IP"]
            tcp = packet["TCP"]

            src = ip.src
            dst = ip.dst

            if tcp.dport == 2404:
                function = "request"
                state.register_asset(dst, role="iec104_server", protocol=self.slug)
                state.register_asset(src, role="iec104_client", protocol=self.slug)
            else:
                function = "response"

            state.register_communication(
                src=src,
                dst=dst,
                protocol=self.slug,
                function=function,
                metadata={
                    "src_port": int(tcp.sport),
                    "dst_port": int(tcp.dport),
                },
            )
        except Exception:
            return
