from __future__ import annotations
from guppy_ics.protocols.base import ProtocolPlugin


OPCUA_PORTS = {4840, 4843}


class OPCUAPlugin(ProtocolPlugin):
    name = "OPC UA"
    slug = "opcua"
    safe_by_default = False
    ports = list(OPCUA_PORTS)

    def match(self, packet) -> bool:
        try:
            return (
                packet.haslayer("IP")
                and packet.haslayer("TCP")
                and (
                    packet["TCP"].sport in OPCUA_PORTS
                    or packet["TCP"].dport in OPCUA_PORTS
                )
            )
        except Exception:
            return False

    def process(self, packet, state) -> None:
        try:
            ip = packet["IP"]
            tcp = packet["TCP"]

            src_ip = ip.src
            dst_ip = ip.dst

            # Server listens on well-known port
            if tcp.dport in OPCUA_PORTS:
                client = src_ip
                server = dst_ip
                direction = "request"
            else:
                client = dst_ip
                server = src_ip
                direction = "response"

            state.register_asset(server, role="opcua_server", protocol=self.slug)
            state.register_asset(client, role="opcua_client", protocol=self.slug)

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
