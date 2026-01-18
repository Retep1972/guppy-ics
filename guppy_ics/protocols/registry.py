from __future__ import annotations

from typing import List, Dict

from guppy_ics.protocols.base import ProtocolPlugin
from guppy_ics.protocols.modbus import ModbusPlugin
from guppy_ics.protocols.profinet import ProfinetPlugin
from guppy_ics.protocols.arp import ArpPlugin
from guppy_ics.protocols.l2l3 import L2L3LinkerPlugin
from guppy_ics.protocols.transport import TransportPlugin
from guppy_ics.protocols.s7comm import S7CommPlugin
from guppy_ics.protocols.opcua import OPCUAPlugin
from guppy_ics.protocols.iec104 import IEC104Plugin


def _all_plugins() -> List[ProtocolPlugin]:
    """
    Instantiate all available protocol plugins.
    This is the single source of truth.
    """
    return [
        ModbusPlugin(),
        ProfinetPlugin(),
        ArpPlugin(),
        L2L3LinkerPlugin(),
        TransportPlugin(),
        S7CommPlugin(),
        OPCUAPlugin(),
        IEC104Plugin(),
    ]


def load_plugins(enabled: List[str] | None = None) -> List[ProtocolPlugin]:
    plugins = _all_plugins()

    if enabled:
        enabled_set = set(enabled)
        always = {"arp", "l2l3", "transport"}
        return [p for p in plugins if p.slug in enabled_set or p.slug in always]

    return plugins


def available_protocols():
    infrastructure = {"arp", "l2l3", "transport"}

    return [
        {
            "slug": p.slug,
            "name": p.name,
            "safe_by_default": getattr(p, "safe_by_default", False),
        }
        for p in _all_plugins()
        if p.slug not in infrastructure
    ]

