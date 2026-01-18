from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from scapy.all import PcapReader  # type: ignore


@dataclass(frozen=True)
class CaptureSource:
    """
    Passive-only sources for packet ingestion.
    For v0 we focus on PCAP. Live capture can be added later.
    """
    pcap_path: str


def iter_packets_from_pcap(pcap_path: str, limit: Optional[int] = None) -> Iterable[object]:
    """
    Stream packets from a PCAP without loading everything into memory.
    """
    count = 0
    with PcapReader(pcap_path) as reader:
        for pkt in reader:
            yield pkt
            count += 1
            if limit is not None and count >= limit:
                break
