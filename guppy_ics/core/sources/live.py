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

    def packets(self) -> Iterable[object]:
        print("[DEBUG] packets() entered:", self.interface, self.bpf_filter)
        """
        Passive streaming sniffing.
        - Runs scapy.sniff() in a background thread (sniff() blocks).
        - Yields packets as they arrive via a queue.
        - Stops when sniff finishes (count/timeout) or on external termination.
        """
        q: Queue = Queue()

        def on_packet(pkt):
            q.put(pkt)

        def sniffer():
            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=on_packet,
                store=False,  # critical: don't buffer in memory
                count=self.packet_limit,
                timeout=self.timeout,
            )
            q.put(None)  # signal end of capture

        t = threading.Thread(target=sniffer, daemon=True)
        t.start()

        while True:
            pkt = q.get()
            if pkt is None:
                break
            yield pkt
