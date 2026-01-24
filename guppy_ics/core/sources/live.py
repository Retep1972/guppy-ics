from scapy.all import sniff
from queue import Queue
from typing import Iterable, Optional
import threading
from guppy_ics.core.sources.base import PacketSource

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

    def packets(self):
        q: Queue = Queue()

        def on_packet(pkt):
            q.put(pkt)

        def sniffer():
            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=on_packet,
                store=False,
                count=self.packet_limit,
                timeout=self.timeout,
            )
            q.put(None)  # signal end

        t = threading.Thread(target=sniffer, daemon=True)
        t.start()

        while True:
            pkt = q.get()
            if pkt is None:
                break
            yield pkt
