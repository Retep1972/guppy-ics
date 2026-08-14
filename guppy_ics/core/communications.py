from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Set


DEFAULT_TRANSPORT_PROTOCOLS = {"ip", "ipv4", "ipv6", "tcp", "udp"}
GENERIC_TRANSPORT_PROTOCOLS = {"tcp", "udp"}


def filter_communications_for_presentation(
    communications: Iterable[Dict[str, Any]],
    *,
    transport_protocols: Optional[Set[str]] = None,
) -> List[Dict[str, Any]]:
    """
    Prefer protocol-specific communications over generic TCP/UDP display rows.
    """
    transports = transport_protocols or DEFAULT_TRANSPORT_PROTOCOLS
    comms = [c for c in communications if isinstance(c, dict)]
    specific_keys = {
        key
        for c in comms
        if _protocol(c) not in transports
        for key in [_stack_key(c)]
        if key is not None
    }

    filtered: List[Dict[str, Any]] = []
    seen_generic = set()
    for comm in comms:
        proto = _protocol(comm)
        if proto in {"ip", "ipv4", "ipv6"}:
            continue

        key = _stack_key(comm)
        if proto in GENERIC_TRANSPORT_PROTOCOLS:
            if key is not None and key in specific_keys:
                continue

            generic_key = (
                comm.get("src_asset_id"),
                comm.get("dst_asset_id"),
                proto,
                comm.get("function"),
                _metadata(comm).get("src_port"),
                _metadata(comm).get("dst_port"),
            )
            if generic_key in seen_generic:
                continue
            seen_generic.add(generic_key)

        filtered.append(comm)

    return filtered


def _stack_key(comm: Dict[str, Any]):
    src = comm.get("src_asset_id")
    dst = comm.get("dst_asset_id")
    if not src or not dst:
        return None
    service_port = _service_port(comm)
    if service_port is None:
        return None
    return tuple(sorted((str(src), str(dst)))), service_port


def _service_port(comm: Dict[str, Any]) -> Optional[int]:
    metadata = _metadata(comm)
    explicit = _as_int(metadata.get("service_port"))
    if explicit is not None:
        return explicit

    src_port = _as_int(metadata.get("src_port"))
    dst_port = _as_int(metadata.get("dst_port"))
    if src_port is None:
        return dst_port
    if dst_port is None:
        return src_port
    if dst_port <= 1024 < src_port:
        return dst_port
    if src_port <= 1024 < dst_port:
        return src_port
    return min(src_port, dst_port)


def _metadata(comm: Dict[str, Any]) -> Dict[str, Any]:
    metadata = comm.get("metadata", {}) or {}
    return metadata if isinstance(metadata, dict) else {}


def _protocol(comm: Dict[str, Any]) -> str:
    return str(comm.get("protocol") or "").lower()


def _as_int(value: Any) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
