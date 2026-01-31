from __future__ import annotations
from guppy_ics.protocols.base import ProtocolPlugin


class TransportPlugin(ProtocolPlugin):
    """
    Infrastructure plugin:
    Matches TCP/UDP traffic but does not register
    communications or assets.

    Exists only to ensure transport layers are
    observable for debugging / future use.
    """
    name = "Transport (TCP/UDP)"
    slug = "transport"
    safe_by_default = True

    def match(self, packet) -> bool:
        try:
            return (
                packet.haslayer("IP")
                and (packet.haslayer("TCP") or packet.haslayer("UDP"))
            )
        except Exception:
            return False

    def process(self, packet, state) -> None:
        # Intentionally empty:
        # transport alone does not imply a meaningful communication
        return
