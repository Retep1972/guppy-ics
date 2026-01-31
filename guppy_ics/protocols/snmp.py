from __future__ import annotations

from guppy_ics.protocols.base import ProtocolPlugin


SNMP_PORTS = {161, 162}


class SNMPPlugin(ProtocolPlugin):
    name = "SNMP"
    slug = "snmp"
    safe_by_default = True
    ports = list(SNMP_PORTS)

    def match(self, packet) -> bool:
        try:
            return (
                packet.haslayer("IP")
                and packet.haslayer("UDP")
                and (
                    packet["UDP"].sport in SNMP_PORTS
                    or packet["UDP"].dport in SNMP_PORTS
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
            if udp.dport == 161:
                client_ip = src_ip
                server_ip = dst_ip
                direction = "request"
            elif udp.sport == 161:
                client_ip = dst_ip
                server_ip = src_ip
                direction = "response"
            elif udp.dport == 162:
                client_ip = src_ip
                server_ip = dst_ip
                direction = "trap"
            else:
                return

            # ----------------------------
            # SNMP version detection
            # ----------------------------
            snmp_version = None
            if packet.haslayer("SNMP"):
                try:
                    version = packet["SNMP"].version
                    if version == 0:
                        snmp_version = "v1"
                    elif version == 1:
                        snmp_version = "v2c"
                    elif version == 3:
                        snmp_version = "v3"
                except Exception:
                    pass

            # ----------------------------
            # SNMP security warning 
            # ----------------------------
            if snmp_version in ("v1", "v2c"):
                state.register_event(
                    protocol="snmp",
                    event_type="insecure_snmp",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    details={
                        "snmp_version": snmp_version,
                        "note": "SNMP uses cleartext authentication (v1/v2c)",
                    },
                )

            # ----------------------------
            # Metadata for communication
            # ----------------------------
            metadata = {
                "src_port": int(udp.sport),
                "dst_port": int(udp.dport),
                "transport": "udp",
            }

            if snmp_version:
                metadata["snmp_version"] = snmp_version


            # ----------------------------
            # Register assets (L3 evidence)
            # ----------------------------
            state.register_asset(
                server_ip,
                role="snmp_agent",
                protocol=self.slug,
                evidence_layer="l3",
            )

            state.register_asset(
                client_ip,
                role="snmp_manager",
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
