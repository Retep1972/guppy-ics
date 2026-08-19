from guppy_ics.core.state import AnalysisState
from guppy_ics.web.routes.upload import asset_topology_display, build_topology_from_communications


def test_topology_display_prefers_known_device_name():
    asset = {
        "identifiers": {"ip": {"141.81.0.193"}, "mac": {"00:1b:1b:02:e6:0f"}},
        "metadata": {"station_name": "switch4"},
        "oads_profile": {"device_type": "network_switch"},
        "role": "network_device",
    }

    assert asset_topology_display(asset) == "switch4 (141.81.0.193)"


def test_topology_display_uses_device_type_when_name_is_unknown():
    asset = {
        "identifier": "00:80:f4:09:51:3b",
        "identifiers": {"ip": {"172.27.224.250"}, "mac": {"00:80:f4:09:51:3b"}},
        "metadata": {},
        "oads_profile": {"device_type": "plc"},
    }

    assert asset_topology_display(asset) == "plc (172.27.224.250)"


def test_topology_display_falls_back_to_role_before_identifier():
    asset = {
        "identifier": "00:1b:1b:02:e6:1e",
        "identifiers": {"mac": {"00:1b:1b:02:e6:1e"}},
        "metadata": {},
        "role": "network_device",
    }

    assert asset_topology_display(asset) == "network device (00:1b:1b:02:e6:1e)"


def test_topology_includes_multicast_media_and_igmp_evidence():
    state = AnalysisState()
    controller = state.register_asset(
        "10.10.20.10",
        protocol="sip",
        evidence_layer="l3",
        metadata={"hostname": "PA controller"},
    )
    endpoint = state.register_asset(
        "10.10.20.21",
        protocol="igmp",
        evidence_layer="l3",
        metadata={"hostname": "Speaker A"},
    )
    state.register_evidence(
        evidence_type="sdp_media",
        protocol="sdp",
        source_asset=controller,
        attributes={
            "media_type": "audio",
            "destination_ip": "239.10.20.5",
            "destination_port": 5004,
            "transport": "RTP/AVP",
        },
    )
    state.register_evidence(
        evidence_type="rtp_stream",
        protocol="rtp",
        source_asset=controller,
        attributes={"dst_ip": "239.10.20.5", "dst_port": 5004, "scope": "multicast"},
    )
    state.register_evidence(
        evidence_type="igmp_membership",
        protocol="igmp",
        source_asset=endpoint,
        attributes={"group": "239.10.20.5", "event": "membership_report"},
    )

    topology = build_topology_from_communications([], state)

    assert "sdp / advertises audio / RTP/AVP -> 239.10.20.5:5004" in topology["PA controller (10.10.20.10)"]
    assert "rtp / sends_rtp -> 239.10.20.5:5004" in topology["PA controller (10.10.20.10)"]
    assert "igmp / joins_multicast -> 239.10.20.5" in topology["Speaker A (10.10.20.21)"]
