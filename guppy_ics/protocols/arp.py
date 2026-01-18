from __future__ import annotations

from guppy_ics.protocols.base import ProtocolPlugin


class ArpPlugin(ProtocolPlugin):
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

            # Optional debug
            # print("ARP:", arp.psrc, arp.hwsrc)

            # Link MAC <-> IP
            if arp.psrc and arp.hwsrc:
                state.link_identifiers(
                    arp.hwsrc,
                    arp.psrc,
                    protocol=self.slug,
                    reason="arp_observed",
                )

            if arp.pdst and arp.hwdst:
                state.link_identifiers(
                    arp.hwdst,
                    arp.pdst,
                    protocol=self.slug,
                    reason="arp_observed",
                )

        except Exception:
            return

