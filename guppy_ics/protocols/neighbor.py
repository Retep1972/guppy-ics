from __future__ import annotations

import re
from typing import Any, Dict

from guppy_ics.protocols.base import ProtocolPlugin


ETHERTYPE_LLDP = 0x88CC
CDP_DEST_MAC = "01:00:0c:cc:cc:cc"
CDP_SNAP_OUI = 0x00000C
CDP_SNAP_CODE = 0x2000


class LLDPPlugin(ProtocolPlugin):
    name = "LLDP"
    slug = "lldp"
    safe_by_default = True

    def match(self, packet) -> bool:
        try:
            return getattr(packet, "type", None) == ETHERTYPE_LLDP and packet.haslayer("Raw")
        except Exception:
            return False

    def process(self, packet, state) -> None:
        try:
            fields = _parse_lldp(bytes(packet["Raw"].load))
            if not fields:
                return

            _register_neighbor_asset(
                state,
                protocol=self.slug,
                src_mac=str(packet.src),
                dst_mac=str(packet.dst),
                fields=fields,
            )
        except Exception:
            return


class CDPPlugin(ProtocolPlugin):
    name = "Cisco Discovery Protocol"
    slug = "cdp"
    safe_by_default = True

    def match(self, packet) -> bool:
        try:
            if str(getattr(packet, "dst", "")).lower() != CDP_DEST_MAC:
                return False
            snap = packet.getlayer("SNAP")
            return (
                snap is not None
                and int(getattr(snap, "OUI", -1)) == CDP_SNAP_OUI
                and int(getattr(snap, "code", -1)) == CDP_SNAP_CODE
                and packet.haslayer("Raw")
            )
        except Exception:
            return False

    def process(self, packet, state) -> None:
        try:
            fields = _parse_cdp(bytes(packet["Raw"].load))
            if not fields:
                return

            _register_neighbor_asset(
                state,
                protocol=self.slug,
                src_mac=str(packet.src),
                dst_mac=str(packet.dst),
                fields=fields,
            )
        except Exception:
            return


def _register_neighbor_asset(
    state,
    *,
    protocol: str,
    src_mac: str,
    dst_mac: str,
    fields: Dict[str, Any],
) -> None:
    metadata = {"raw_protocol_identity": {protocol: fields}}
    if fields.get("system_name"):
        metadata["hostname"] = fields["system_name"]
    if fields.get("order_number"):
        metadata["order_number"] = fields["order_number"]
    if fields.get("firmware_version"):
        metadata["firmware_version"] = fields["firmware_version"]
    if fields.get("hardware_version"):
        metadata["hardware_version"] = fields["hardware_version"]

    asset_id = state.register_asset(
        src_mac,
        role="network_device",
        protocol=protocol,
        metadata=metadata,
        evidence_layer="l2",
    )
    if asset_id in state.assets and fields.get("system_name"):
        state.assets[asset_id]["identifiers"].setdefault("hostname", set()).add(fields["system_name"])

    if fields.get("management_address"):
        state.link_identifiers(
            src_mac,
            fields["management_address"],
            protocol=protocol,
            reason=f"{protocol}_management_address",
        )

    state.register_evidence(
        evidence_type=protocol,
        protocol=protocol,
        source_asset=asset_id,
        attributes={**fields, "src_mac": src_mac, "dst_mac": dst_mac},
    )


def _parse_lldp(payload: bytes) -> Dict[str, Any]:
    fields: Dict[str, Any] = {}
    offset = 0
    while offset + 2 <= len(payload):
        header = int.from_bytes(payload[offset : offset + 2], "big")
        offset += 2
        tlv_type = header >> 9
        length = header & 0x1FF
        if tlv_type == 0:
            break
        if length < 0 or offset + length > len(payload):
            break
        value = payload[offset : offset + length]
        offset += length

        if tlv_type == 1 and len(value) >= 2:
            fields["chassis_id"] = _decode_tlv_string(value[1:])
        elif tlv_type == 2 and len(value) >= 2:
            fields["port_id"] = _decode_tlv_string(value[1:])
        elif tlv_type == 4:
            fields["port_description"] = _decode_tlv_string(value)
        elif tlv_type == 5:
            fields["system_name"] = _decode_tlv_string(value)
        elif tlv_type == 6:
            description = _decode_tlv_string(value)
            fields["system_description"] = description
            fields.update(_identity_from_description(description))
        elif tlv_type == 7 and len(value) >= 4:
            fields["system_capabilities"] = value.hex()
        elif tlv_type == 8:
            management_address = _parse_lldp_management_address(value)
            if management_address:
                fields["management_address"] = management_address

    return {k: v for k, v in fields.items() if v not in (None, "", [], {})}


def _parse_cdp(payload: bytes) -> Dict[str, Any]:
    if len(payload) < 4:
        return {}

    fields: Dict[str, Any] = {
        "cdp_version": payload[0],
        "ttl": payload[1],
    }
    offset = 4
    while offset + 4 <= len(payload):
        tlv_type = int.from_bytes(payload[offset : offset + 2], "big")
        length = int.from_bytes(payload[offset + 2 : offset + 4], "big")
        if length < 4 or offset + length > len(payload):
            break
        value = payload[offset + 4 : offset + length]
        offset += length

        if tlv_type == 0x0001:
            fields["device_id"] = _decode_tlv_string(value)
            fields["system_name"] = fields["device_id"]
        elif tlv_type == 0x0003:
            fields["port_id"] = _decode_tlv_string(value)
        elif tlv_type == 0x0004 and len(value) >= 4:
            fields["capabilities"] = hex(int.from_bytes(value[-4:], "big"))
        elif tlv_type == 0x0005:
            software = _decode_tlv_string(value)
            fields["software_version"] = software
            fields["system_description"] = software
            fields.update(_identity_from_description(software))
        elif tlv_type == 0x0006:
            platform = _decode_tlv_string(value)
            fields["platform"] = platform
            fields["model"] = platform
        elif tlv_type in (0x0002, 0x0016):
            address = _parse_cdp_addresses(value)
            if address:
                fields.setdefault("management_address", address)
        elif tlv_type == 0x0009:
            fields["vtp_management_domain"] = _decode_tlv_string(value)

    return {k: v for k, v in fields.items() if v not in (None, "", [], {})}


def _parse_lldp_management_address(value: bytes) -> str | None:
    if len(value) < 2:
        return None
    addr_len = value[0]
    if addr_len < 2 or len(value) < 1 + addr_len:
        return None
    subtype = value[1]
    address = value[2 : 1 + addr_len]
    if subtype == 1 and len(address) == 4:
        return ".".join(str(part) for part in address)
    return None


def _parse_cdp_addresses(value: bytes) -> str | None:
    if len(value) < 4:
        return None
    count = int.from_bytes(value[0:4], "big")
    offset = 4
    for _ in range(min(count, 8)):
        if offset + 8 > len(value):
            return None
        protocol_type = value[offset]
        protocol_len = value[offset + 1]
        protocol = value[offset + 2 : offset + 2 + protocol_len]
        offset += 2 + protocol_len
        if offset + 2 > len(value):
            return None
        address_len = int.from_bytes(value[offset : offset + 2], "big")
        offset += 2
        address = value[offset : offset + address_len]
        offset += address_len
        if protocol_type == 1 and protocol == b"\xcc" and address_len == 4:
            return ".".join(str(part) for part in address)
    return None


def _decode_tlv_string(value: bytes) -> str:
    text = value.decode("utf-8", errors="ignore")
    text = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()[:500]


def _identity_from_description(text: str) -> Dict[str, str]:
    identity: Dict[str, str] = {}
    order = re.search(r"\b(6GK[0-9A-Z -]{6,}[0-9A-Z])\b", text, flags=re.IGNORECASE)
    if order:
        identity["order_number"] = re.sub(r"\s+", " ", order.group(1)).strip()

    firmware = re.search(r"\bFW\s*:\s*([A-Za-z]?[0-9][A-Za-z0-9_.-]*)", text, flags=re.IGNORECASE)
    if firmware:
        identity["firmware_version"] = firmware.group(1)

    hardware = re.search(r"\bHW\s*:\s*([A-Za-z]?[0-9][A-Za-z0-9_.-]*)", text, flags=re.IGNORECASE)
    if hardware:
        identity["hardware_version"] = hardware.group(1)

    return identity
