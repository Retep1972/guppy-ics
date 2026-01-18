from typing import Iterable, Optional

from scapy.all import sniff  # type: ignore

from guppy_ics.core.sources.base import PacketSource

"""Live capture is passive-only but still potentially disruptive if misused.
Guppy ICS should only be connected to SPAN/mirror ports or network taps."""

class LiveInterfaceSource(PacketSource):
    def __init__(
        self,
        interface: str,
        *,
        bpf_filter: Optional[str] = None,
        packet_limit: Optional[int] = None,
        timeout: Optional[int] = None,
    ):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.packet_limit = packet_limit
        self.timeout = timeout

    def packets(self) -> Iterable[object]:
        """
        Passive sniffing only.
        Requires Npcap (Windows) or root/cap_net_raw (Linux).
        """

        packets = sniff(
            iface=self.interface,
            filter=self.bpf_filter,
            count=self.packet_limit,
            timeout=self.timeout,
            store=True,   # we immediately yield then discard
        )

        for pkt in packets:
            yield pkt
