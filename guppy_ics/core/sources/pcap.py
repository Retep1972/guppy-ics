from pathlib import Path
from typing import Iterable, Optional

from scapy.all import PcapReader  # type: ignore

from guppy_ics.core.sources.base import PacketSource


class PcapFileSource(PacketSource):
    def __init__(self, path: str | Path, *, limit: Optional[int] = None):
        self.path = Path(path)
        self.limit = limit

        if not self.path.exists():
            raise FileNotFoundError(self.path)

    def packets(self) -> Iterable[object]:
        count = 0
        with PcapReader(str(self.path)) as reader:
            for pkt in reader:
                yield pkt
                count += 1
                if self.limit and count >= self.limit:
                    break
