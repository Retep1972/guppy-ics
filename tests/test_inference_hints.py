from guppy_ics.core.state import AnalysisState


def test_network_device_with_multiple_macs_is_not_marked_likely_vm():
    state = AnalysisState()
    state.register_asset("00:1b:1b:02:e6:1e", role="network_device", protocol="profinet", evidence_layer="l2")
    state.link_identifiers(
        "00:1b:1b:02:e6:1e",
        "00:1b:1b:02:e6:1f",
        protocol="lldp",
        reason="same_switch_management_identity",
    )

    state.finalize_asset_visibility()

    asset = state.assets[state.asset_index["00:1b:1b:02:e6:1e"]]
    hints = asset.get("metadata", {}).get("inference_hints", [])
    assert "likely_vm" not in hints
    assert "multi_mac" not in hints


def test_non_network_device_with_multiple_macs_gets_neutral_hint():
    state = AnalysisState()
    state.register_asset("00:0c:29:9d:9e:9e", protocol="modbus", evidence_layer="l3")
    state.link_identifiers(
        "00:0c:29:9d:9e:9e",
        "00:0c:29:e6:14:21",
        protocol="dhcp",
        reason="identity_link",
    )

    state.finalize_asset_visibility()

    asset = state.assets[state.asset_index["00:0c:29:9d:9e:9e"]]
    hints = asset.get("metadata", {}).get("inference_hints", [])
    assert "multi_mac" in hints
    assert "likely_vm" not in hints
