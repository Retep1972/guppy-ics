from guppy_ics.protocols.base import ProtocolPlugin


class IPv6DetectionPlugin(ProtocolPlugin):
    """
    Infrastructure plugin:
    Detects presence of IPv6 and links IPv6 addresses
    to existing assets for situational awareness.

    IPv6 detection does NOT imply L3 application visibility.
    """
    slug = "ipv6"
    name = "IPv6 Detection"
    safe_by_default = True

    def match(self, packet) -> bool:
        try:
            return packet.haslayer("IPv6")
        except Exception:
            return False

    def process(self, packet, state) -> None:
        try:
            ip6 = packet["IPv6"]

            src_ipv6 = ip6.src
            dst_ipv6 = ip6.dst

            src_asset_id = None
            dst_asset_id = None

            # -------------------------------------------------
            # Link IPv6 addresses to existing assets via MAC
            # (identity enrichment only)
            # -------------------------------------------------
            if hasattr(packet, "src") and ":" in str(packet.src):
                src_asset_id = state.link_identifiers(
                    packet.src,           # MAC
                    src_ipv6,              # IPv6
                    reason="ipv6_observed",
                )

            if hasattr(packet, "dst") and ":" in str(packet.dst):
                dst_asset_id = state.link_identifiers(
                    packet.dst,           # MAC
                    dst_ipv6,              # IPv6
                    reason="ipv6_observed",
                )

            # -------------------------------------------------
            # Register informational event
            # -------------------------------------------------
            state.register_event(
                protocol="ipv6",
                event_type="ipv6_detected",
                src_ip=src_ipv6,
                dst_ip=dst_ipv6,
                details={
                    "src_asset_id": src_asset_id,
                    "dst_asset_id": dst_asset_id,
                    "note": "IPv6 traffic observed (identity only, no application inference)",
                },
            )

        except Exception:
            # Never break analysis on malformed packets
            return
