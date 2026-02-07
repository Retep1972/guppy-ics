import time
from scapy.utils import PcapReader

class LivePCAPSource:
    """
    Replay a PCAP file as a live packet stream.
    """

    def __init__(self, pcap_path, *, speed=1.0, loop=False, cancel_token=None):
        self.pcap_path = pcap_path
        self.speed = speed
        self.loop = loop
        self.cancel_token = cancel_token

    def packets(self):
        while True:
            with PcapReader(self.pcap_path) as reader:
                prev_ts = None

                for pkt in reader:
                    if self.cancel_token and self.cancel_token.is_cancelled():
                        return

                    if prev_ts is not None:
                        delta = float(pkt.time - prev_ts)
                        if delta > 0:
                            time.sleep(delta / self.speed)


                    prev_ts = pkt.time
                    yield pkt

            if not self.loop:
                break
