from __future__ import annotations

import struct

from guppy_ics.protocols.base import ProtocolPlugin


ETHERTYPE_PROFINET = 0x8892
DCP_OPTION_DEVICE_PROPERTIES = 0x02
DCP_SUBOPTION_STATION_NAME = 0x02


class ProfinetPlugin(ProtocolPlugin):
    name = "PROFINET IO"
    slug = "profinet"
    safe_by_default = False
    ports = [34962, 34963, 34964]

    def match(self, packet) -> bool:
        try:
            # 1Native Ethernet PNIO
            if hasattr(packet, "type") and packet.type == ETHERTYPE_PROFINET:
                return True

            # Scapy-decoded Raw PNIO payload
            if packet.haslayer("Raw"):
                raw = bytes(packet["Raw"].load)
                if len(raw) >= 2:
                    frame_id = struct.unpack(">H", raw[0:2])[0]

                    # RTC1 or DCP frame IDs
                    if (
                        0x8000 <= frame_id <= 0xBFFF
                        or frame_id in (0xFEFE, 0xFEFD)
                    ):
                        return True

            return False
        except Exception:
            return False
        
    def process(self, packet, state) -> None:
        #print("PROFINET packet seen")
        try:
            # ----------------------------
            # Layer 2 identifiers (default)
            # ----------------------------
            src_id = packet.src
            dst_id = packet.dst
            identifier_type = "mac"
            #print(packet)

            # ----------------------------
            # Future-proof: IP-based PNIO
            # ----------------------------
            if packet.haslayer("IP"):
                ip = packet["IP"]
                try:
                    if hasattr(packet, "src") and ":" in str(packet.src):
                        state.link_identifiers(packet.src, ip.src, protocol=self.slug, reason="l2_l3_observed")
                    if hasattr(packet, "dst") and ":" in str(packet.dst):
                        state.link_identifiers(packet.dst, ip.dst, protocol=self.slug, reason="l2_l3_observed")
                except Exception:
                    pass

            # PROFINET payload is always in Raw (especially with VLAN)
            if not packet.haslayer("Raw"):
                return

            payload = bytes(packet["Raw"].load)
            if len(payload) < 2:
                return

            frame_id = struct.unpack(">H", payload[0:2])[0]

            # -------------------------------------------------
            # RTC1 / cyclic IO frames (0x8000–0xBFFF)
            # -------------------------------------------------
            # RTC1 cyclic IO
            if 0x8000 <= frame_id <= 0xBFFF:
                state.register_asset(packet.src, protocol=self.slug)
                state.register_asset(packet.dst, protocol=self.slug)

                state.register_communication(
                    src=packet.src,
                    dst=packet.dst,
                    protocol=self.slug,
                    function="rtc1_io",
                    metadata={"frame_id": hex(frame_id)},
                )
                return

            # -----------------------------------------
            # DCP Identify / Set (0xFEFE / 0xFEFD)
            # -----------------------------------------
            if frame_id not in (0xFEFE, 0xFEFD):
                return

            offset = 10  # fixed DCP header length
            station_name = None

            while offset + 4 <= len(payload):
                option = payload[offset]
                suboption = payload[offset + 1]
                length = struct.unpack(">H", payload[offset + 2:offset + 4])[0]

                data_start = offset + 4
                data_end = data_start + length
                if data_end > len(payload):
                    break

                data = payload[data_start:data_end]

                if (
                    option == DCP_OPTION_DEVICE_PROPERTIES
                    and suboption == DCP_SUBOPTION_STATION_NAME
                ):
                    try:
                        station_name = data.rstrip(b"\x00").decode(
                            "ascii", errors="ignore"
                        )
                    except Exception:
                        pass

                offset = data_end
                if offset % 2:
                    offset += 1

            metadata = {}
            if station_name:
                metadata["station_name"] = station_name

            state.register_asset(
                src_id,
                role="profinet_device",
                protocol=self.slug,
                metadata=metadata if metadata else None,
            )
            state.register_asset(
                dst_id,
                role="profinet_device",
                protocol=self.slug,
            )

            state.register_communication(
                src=src_id,
                dst=dst_id,
                protocol=self.slug,
                function="dcp",
                metadata={"identifier_type": identifier_type},
            )

        except Exception:
            # Never break analysis on malformed frames
            return

