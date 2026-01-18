from __future__ import annotations

from guppy_ics.protocols.base import ProtocolPlugin


class ModbusPlugin(ProtocolPlugin):
    name = "Modbus TCP"
    slug = "modbus"
    safe_by_default = True
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
            # Must be IP + TCP for Modbus
            if not packet.haslayer("IP") or not packet.haslayer("TCP"):
                return

            ip = packet["IP"]
            tcp = packet["TCP"]

            src_ip = ip.src
            dst_ip = ip.dst

            # 🔗 Link L2 <-> L3 identities FIRST
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

            # Heuristic roles
            if tcp.dport == 502:
                state.register_asset(src_ip, role="client", protocol=self.slug)
                state.register_asset(dst_ip, role="plc", protocol=self.slug)
                direction = "request"
            else:
                state.register_asset(src_ip, role="plc", protocol=self.slug)
                state.register_asset(dst_ip, role="client", protocol=self.slug)
                direction = "response"

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

        except Exception as e:
            # TEMP: log once while debugging
            print("Modbus process error:", e)
            return

