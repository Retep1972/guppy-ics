from __future__ import annotations

from typing import Optional, Callable

from guppy_ics.core.dispatcher import ProtocolDispatcher
from guppy_ics.core.state import AnalysisState
from guppy_ics.protocols.registry import load_plugins
from guppy_ics.core.sources.base import PacketSource
from guppy_ics.core.sources.pcap import PcapFileSource
from guppy_ics.core.control import CancelToken


def analyze_pcap(
    path: str,
    *,
    enabled_protocols: Optional[list[str]] = None,
    limit: Optional[int] = None,
    progress_cb: Optional[Callable[[int], None]] = None,
    cancel_token: Optional[CancelToken] = None,
) -> AnalysisState:
    source = PcapFileSource(path, limit=limit)
    return analyze_source(
        source,
        enabled_protocols=enabled_protocols,
        progress_cb=progress_cb,
        cancel_token=cancel_token,
    )

def analyze_source(
    source: PacketSource,
    *,
    enabled_protocols: Optional[list[str]] = None,
    progress_cb: Optional[Callable[[int], None]] = None,
    progress_interval: int = 1000,
    cancel_token: Optional[CancelToken] = None,
) -> AnalysisState:
    plugins = load_plugins(enabled=enabled_protocols)
    dispatcher = ProtocolDispatcher(plugins)
    state = AnalysisState()

    packet_count = 0

    for pkt in source.packets():
        #print(pkt.summary())
        if cancel_token and cancel_token.is_cancelled():
            break

        dispatcher.dispatch(pkt, state)
        packet_count += 1

        if progress_cb and packet_count % progress_interval == 0:
            progress_cb(packet_count)

    if progress_cb:
        progress_cb(packet_count)

    state.finalize_asset_visibility()
    #for a in state.assets.values():
        #print(a["identifiers"], a["visibility"], a["protocols"])
    return state
