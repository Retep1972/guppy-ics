from __future__ import annotations

from guppy_ics.protocols.base import ProtocolPlugin
from guppy_ics.protocols.mac_helper import is_valid_mac

class ArpPlugin(ProtocolPlugin):
    """
    Infrastructure plugin:
    Uses ARP to link MAC <-> IPv4 identities.

    ARP provides identity evidence only.
    It must not imply application protocols,
    visibility, or communications.
    """
    name = "ARP"
    slug = "arp"
    safe_by_default = True

    def match(self, packet) -> bool:
        try:
            return packet.haslayer("ARP")
        except Exception:
            return False

    def process(self, packet, state) -> None:
        try:
            if not packet.haslayer("ARP"):
                return

            arp = packet["ARP"]

            # ----------------------------
            # Link MAC <-> IPv4 identities
            # (identity enrichment only)
            # ----------------------------
            if is_valid_mac(arp.hwsrc) and arp.hwsrc:
                state.link_identifiers(
                    arp.hwsrc,
                    arp.psrc,
                    reason="arp_observed",
                )

            if is_valid_mac(arp.pdst) and arp.hwdst:
                state.link_identifiers(
                    arp.hwdst,
                    arp.pdst,
                    reason="arp_observed",
                )

        except Exception:
            # Never break analysis on malformed frames
            return
