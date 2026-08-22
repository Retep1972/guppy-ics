from pathlib import Path

from guppy_ics.core.state import AnalysisState
from guppy_ics.segmentation import assess_segmentation, write_segmentation_outputs


def _asset(state, identifier, *, role=None, protocol=None, metadata=None, oads_profile=None):
    asset_id = state.register_asset(identifier, role=role, protocol=protocol, metadata=metadata)
    if oads_profile:
        state.assets[asset_id]["oads_profile"] = oads_profile
    return asset_id


def _comm(state, src, dst, protocol, *, dst_port=None, function=None):
    state.register_communication(
        src=src,
        dst=dst,
        protocol=protocol,
        function=function,
        metadata={"transport": "tcp", "dst_port": dst_port} if dst_port else {"transport": "tcp"},
    )


def test_segmentation_healthy_small_ot_environment_has_no_critical_findings():
    state = AnalysisState()
    _asset(state, "10.0.0.10", role="engineering workstation", metadata={"hostname": "ENG-01"})
    _asset(state, "10.0.0.20", role="plc", protocol="s7comm")
    _asset(state, "10.0.0.30", role="hmi", metadata={"hostname": "HMI-01"})
    _asset(state, "10.0.0.40", metadata={"hostname": "Historian-01"})
    state.assets[state.asset_index["10.0.0.40"]]["oads_profile"] = {"device_type": "historian"}
    _asset(state, "10.0.0.50", role="server")

    _comm(state, "10.0.0.10", "10.0.0.20", "s7comm", dst_port=102)
    _comm(state, "10.0.0.30", "10.0.0.20", "s7comm", dst_port=102)
    _comm(state, "10.0.0.20", "10.0.0.40", "opcua", dst_port=4840)
    _comm(state, "10.0.0.40", "10.0.0.50", "https", dst_port=443)
    state.finalize_asset_visibility()

    assessment = assess_segmentation(state)

    assert not [f for f in assessment.findings if f.severity == "critical"]
    assert {s.category for s in assessment.segments} >= {"engineering", "operations", "process_control", "ot_services"}


def test_segmentation_enterprise_laptop_to_plc_is_high_risky():
    state = AnalysisState()
    _asset(state, "10.0.1.10", role="workstation")
    _asset(state, "10.0.2.20", role="plc", protocol="s7comm")
    _comm(state, "10.0.1.10", "10.0.2.20", "s7comm", dst_port=102)

    assessment = assess_segmentation(state)

    finding = assessment.findings[0]
    assert finding.rule_id == "SEG-CROSS-001"
    assert finding.severity == "high"
    assert finding.assessment == "RISKY"


def test_segmentation_camera_to_nvr_expected_but_camera_to_plc_risky():
    state = AnalysisState()
    _asset(state, "10.0.3.10", protocol="onvif", oads_profile={"device_type": "camera"})
    _asset(state, "10.0.3.20", protocol="rtsp", oads_profile={"device_type": "nvr"})
    _asset(state, "10.0.4.20", role="plc", protocol="s7comm")
    _comm(state, "10.0.3.10", "10.0.3.20", "rtsp", dst_port=554)
    _comm(state, "10.0.3.10", "10.0.4.20", "s7comm", dst_port=102)

    assessment = assess_segmentation(state)

    assert any(f.rule_id == "SEG-CROSS-004" and f.severity == "high" for f in assessment.findings)
    assert any(r.assessment == "EXPECTED" and r.protocol == "rtsp" for r in assessment.communication_recommendations)


def test_segmentation_unknown_asset_to_plc_is_review_not_deny():
    state = AnalysisState()
    _asset(state, "10.0.5.10")
    _asset(state, "10.0.5.20", role="plc", protocol="modbus")
    _comm(state, "10.0.5.10", "10.0.5.20", "tcp", dst_port=502)

    assessment = assess_segmentation(state)

    assert assessment.findings[0].assessment == "REVIEW"
    assert all(intent.action != "DENY" for intent in assessment.firewall_intent)


def test_segmentation_direct_internet_to_plc_is_critical():
    state = AnalysisState()
    _asset(state, "8.8.8.8")
    _asset(state, "10.0.6.20", role="plc", protocol="modbus")
    _comm(state, "8.8.8.8", "10.0.6.20", "modbus", dst_port=502)

    assessment = assess_segmentation(state)

    assert any(f.rule_id == "SEG-CROSS-002" and f.severity == "critical" for f in assessment.findings)
    assert assessment.posture == "poor"


def test_segmentation_operational_audio_group_is_inferred():
    state = AnalysisState()
    _asset(state, "10.0.7.10", protocol="sip", metadata={"hostname": "sip-controller"})
    _asset(state, "10.0.7.11", protocol="rtp", metadata={"hostname": "speaker-01"})
    _comm(state, "10.0.7.10", "10.0.7.11", "sip", dst_port=5060)
    _comm(state, "10.0.7.10", "10.0.7.11", "rtp", dst_port=5004)

    assessment = assess_segmentation(state)

    assert any(s.category == "operational_audio" for s in assessment.segments)
    assert not [f for f in assessment.findings if f.severity in {"critical", "high"}]


def test_segmentation_broad_pivot_asset_gets_review_finding():
    state = AnalysisState()
    _asset(state, "10.0.8.10", role="workstation")
    targets = [
        ("10.0.8.20", "plc", "s7comm"),
        ("10.0.8.30", "hmi", "http"),
        ("10.0.8.40", None, "onvif"),
        ("10.0.8.50", None, "sip"),
    ]
    for ip, role, protocol in targets:
        _asset(state, ip, role=role, protocol=protocol)
        _comm(state, "10.0.8.10", ip, protocol)

    assessment = assess_segmentation(state)

    assert any(f.rule_id == "SEG-GRAPH-001" for f in assessment.findings)


def test_segmentation_outputs_are_written(tmp_path: Path):
    state = AnalysisState()
    _asset(state, "10.0.9.10", role="engineering workstation", metadata={"hostname": "ENG-01"})
    _asset(state, "10.0.9.20", role="plc", protocol="s7comm", metadata={"station_name": "PLC-01"})
    _comm(state, "10.0.9.10", "10.0.9.20", "s7comm", dst_port=102)

    assessment = assess_segmentation(state)
    outputs = write_segmentation_outputs(assessment, tmp_path)
    report = outputs["segmentation_report"].read_text(encoding="utf-8")

    assert outputs["segmentation_report"].exists()
    assert (tmp_path / "segments.json").exists()
    assert (tmp_path / "communication_matrix.csv").exists()
    assert "IEC 62443 compliance checker" in report
    assert "Segment Topology Overview" in report
    assert "ENG-01" in report
    assert "PLC-01" in report
