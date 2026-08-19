from scapy.layers.l2 import Dot3, Ether, LLC, SNAP
from scapy.packet import Raw

from guppy_ics.core.state import AnalysisState
from guppy_ics.integrations.oads import build_observations_payload
from guppy_ics.protocols.neighbor import CDPPlugin, LLDPPlugin


def _lldp_tlv(tlv_type: int, value: bytes) -> bytes:
    header = (tlv_type << 9) | len(value)
    return header.to_bytes(2, "big") + value


def _cdp_tlv(tlv_type: int, value: bytes) -> bytes:
    return tlv_type.to_bytes(2, "big") + (len(value) + 4).to_bytes(2, "big") + value


def test_lldp_extracts_switch_identity_for_oads():
    system_description = (
        b"Siemens, SIMATIC NET, SCALANCE X212-2, "
        b"6GK5 212-2BB00-2AA3, HW: 7, FW: V4.02"
    )
    payload = (
        _lldp_tlv(1, b"\x07switch1")
        + _lldp_tlv(2, b"\x07port-001")
        + _lldp_tlv(3, b"\x00\x14")
        + _lldp_tlv(4, b"Siemens, SIMATIC NET, Ethernet Switch Port 01")
        + _lldp_tlv(5, b"switch1")
        + _lldp_tlv(6, system_description)
        + b"\x00\x00"
    )
    packet = (
        Ether(src="00:1b:1b:02:e6:1f", dst="01:80:c2:00:00:0e", type=0x88CC)
        / Raw(payload)
    )
    state = AnalysisState()
    plugin = LLDPPlugin()

    assert plugin.match(packet)
    plugin.process(packet, state)

    asset = state.assets[state.asset_index["00:1b:1b:02:e6:1f"]]
    raw_identity = asset["metadata"]["raw_protocol_identity"]["lldp"]
    assert asset["metadata"]["hostname"] == "switch1"
    assert raw_identity["system_description"].startswith("Siemens, SIMATIC NET")
    assert raw_identity["order_number"] == "6GK5 212-2BB00-2AA3"
    assert raw_identity["firmware_version"] == "V4.02"
    assert raw_identity["hardware_version"] == "7"

    oads_payload = build_observations_payload(state, "capture-1")
    observed = {(obs["protocol"], obs["field"], obs["value"]) for obs in oads_payload["observations"]}
    assert ("lldp", "system_description", raw_identity["system_description"]) in observed
    assert ("lldp", "order_number", "6GK5 212-2BB00-2AA3") in observed
    assert ("lldp", "firmware_version", "V4.02") in observed


def test_cdp_extracts_switch_identity_and_management_address_for_oads():
    address_value = (
        (1).to_bytes(4, "big")
        + b"\x01\x01\xcc"
        + (4).to_bytes(2, "big")
        + bytes([141, 81, 0, 224])
    )
    software = b"Cisco IOS Software, C3750 Software, Version 12.2(50)SE5"
    cdp_payload = (
        b"\x02\xb4\x00\x00"
        + _cdp_tlv(0x0001, b"SW-SR-CORE")
        + _cdp_tlv(0x0002, address_value)
        + _cdp_tlv(0x0003, b"GigabitEthernet3/0/23")
        + _cdp_tlv(0x0005, software)
        + _cdp_tlv(0x0006, b"cisco WS-C3750G-24TS-1U")
    )
    packet = (
        Dot3(src="64:ae:0c:34:ab:97", dst="01:00:0c:cc:cc:cc")
        / LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
        / SNAP(OUI=0x00000C, code=0x2000)
        / Raw(cdp_payload)
    )
    state = AnalysisState()
    plugin = CDPPlugin()

    assert plugin.match(packet)
    plugin.process(packet, state)

    asset = state.assets[state.asset_index["64:ae:0c:34:ab:97"]]
    raw_identity = asset["metadata"]["raw_protocol_identity"]["cdp"]
    assert asset["metadata"]["hostname"] == "SW-SR-CORE"
    assert raw_identity["model"] == "cisco WS-C3750G-24TS-1U"
    assert raw_identity["management_address"] == "141.81.0.224"
    assert "141.81.0.224" in state.asset_index

    oads_payload = build_observations_payload(state, "capture-1")
    observed = {(obs["protocol"], obs["field"], obs["value"]) for obs in oads_payload["observations"]}
    assert ("cdp", "device_id", "SW-SR-CORE") in observed
    assert ("cdp", "model", "cisco WS-C3750G-24TS-1U") in observed
    assert ("cdp", "management_address", "141.81.0.224") in observed
