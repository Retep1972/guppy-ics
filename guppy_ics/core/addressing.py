from __future__ import annotations

import ipaddress
from typing import Optional


def classify_ip_address(value: str | None) -> Optional[str]:
    """
    Classify IP addresses that should not become ordinary endpoint assets.
    """
    if not value:
        return None

    try:
        ip = ipaddress.ip_address(str(value))
    except ValueError:
        return None

    if ip.version == 4:
        if str(ip) == "255.255.255.255":
            return "limited_broadcast"
        if ip.is_unspecified:
            return "unspecified"
        if ip.is_multicast:
            return "multicast"
        if str(ip).endswith(".255"):
            return "subnet_broadcast"
        if str(ip).endswith(".0"):
            return "network_address"
        return None

    if ip.is_unspecified:
        return "unspecified"
    if ip.is_multicast:
        return "multicast"
    return None


def is_special_ip_address(value: str | None) -> bool:
    return classify_ip_address(value) is not None


def communication_scope(dst_ip: str | None, dst_mac: str | None = None) -> str:
    classification = classify_ip_address(dst_ip)
    if classification in {"limited_broadcast", "subnet_broadcast"}:
        return "broadcast"
    if classification == "multicast":
        return "multicast"
    if dst_mac and str(dst_mac).lower() == "ff:ff:ff:ff:ff:ff":
        return "broadcast"
    if dst_mac:
        try:
            if int(str(dst_mac).split(":")[0], 16) & 1:
                return "multicast"
        except (ValueError, IndexError):
            pass
    return "unicast"
