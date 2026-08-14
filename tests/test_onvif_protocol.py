from scapy.all import Ether, IP, TCP, Raw

from guppy_ics.core.state import AnalysisState
from guppy_ics.integrations.oads import build_observations_payload
from guppy_ics.protocols.onvif import ONVIFPlugin
from guppy_ics.protocols.profinet import ProfinetPlugin
from guppy_ics.protocols.registry import available_protocols, load_plugins


def test_onvif_http_registers_camera_and_client():
    plugin = ONVIFPlugin()
    state = AnalysisState()
    pkt = (
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        / IP(src="172.22.10.203", dst="172.22.10.251")
        / TCP(sport=53189, dport=80)
        / Raw(load=b"POST /onvif/media_service HTTP/1.1\r\n\r\n")
    )

    assert plugin.match(pkt)
    plugin.process(pkt, state)

    camera = state.assets[state.asset_index["172.22.10.251"]]
    client = state.assets[state.asset_index["172.22.10.203"]]
    comm = next(iter(state.communications.values()))

    assert camera["role"] == "camera"
    assert client["role"] == "video_client"
    assert "onvif" in camera["protocols"]
    assert comm["protocol"] == "onvif"
    assert comm["function"] == "onvif_http"
    assert comm["metadata"]["service_path"] == "/onvif/media_service"


def test_onvif_rtsp_registers_camera_stream_without_profinet_false_positive():
    onvif = ONVIFPlugin()
    profinet = ProfinetPlugin()
    state = AnalysisState()
    rtsp_pkt = (
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        / IP(src="172.22.10.203", dst="172.22.10.251")
        / TCP(sport=53196, dport=554)
        / Raw(load=b"OPTIONS rtsp://172.22.10.251/rtsp_tunnel RTSP/1.0\r\n\r\n")
    )
    rtp_like_pkt = (
        Ether(src="66:77:88:99:aa:bb", dst="00:11:22:33:44:55")
        / IP(src="172.22.10.251", dst="172.22.10.203")
        / TCP(sport=554, dport=53196)
        / Raw(load=b"\x80\xe0\x00\x01" + b"\x00" * 24)
    )

    assert onvif.match(rtsp_pkt)
    assert onvif.match(rtp_like_pkt)
    assert not profinet.match(rtp_like_pkt)

    onvif.process(rtsp_pkt, state)
    onvif.process(rtp_like_pkt, state)

    camera = state.assets[state.asset_index["172.22.10.251"]]
    assert camera["role"] == "camera"
    assert "onvif" in camera["protocols"]
    assert len(state.communications) == 1


def test_onvif_is_available_and_loadable_by_slug():
    available_protocol_map = {proto["slug"]: proto for proto in available_protocols()}
    loaded = {plugin.slug for plugin in load_plugins(enabled=["onvif"])}
    safe_default_loaded = {plugin.slug for plugin in load_plugins(enabled=[])}

    assert "onvif" in available_protocol_map
    assert available_protocol_map["onvif"]["safe_by_default"] is True
    assert "onvif" in loaded
    assert "onvif" in safe_default_loaded


def test_onvif_device_information_is_submitted_to_oads_as_raw_fields():
    plugin = ONVIFPlugin()
    state = AnalysisState()
    pkt = (
        Ether(src="66:77:88:99:aa:bb", dst="00:11:22:33:44:55")
        / IP(src="172.22.10.251", dst="172.22.10.203")
        / TCP(sport=80, dport=53189)
        / Raw(
            load=(
                b"HTTP/1.1 200 OK\r\n\r\n"
                b"<tds:GetDeviceInformationResponse>"
                b"<tds:Manufacturer>Axis</tds:Manufacturer>"
                b"<tds:Model>AXIS P1375</tds:Model>"
                b"<tds:FirmwareVersion>10.12.0</tds:FirmwareVersion>"
                b"<tds:SerialNumber>ABC123</tds:SerialNumber>"
                b"<tds:HardwareId>HW-1</tds:HardwareId>"
                b"</tds:GetDeviceInformationResponse>"
            )
        )
    )

    assert plugin.match(pkt)
    plugin.process(pkt, state)

    payload = build_observations_payload(state, "capture")
    observed = {
        (obs["protocol"], obs["field"], obs["value"])
        for obs in payload["observations"]
    }

    assert ("onvif", "manufacturer", "Axis") in observed
    assert ("onvif", "manufacturer_name", "Axis") in observed
    assert ("onvif", "model", "AXIS P1375") in observed
    assert ("onvif", "firmware_version", "10.12.0") in observed
    assert ("onvif", "software_version", "10.12.0") in observed
    assert ("onvif", "serial_number", "ABC123") in observed
    assert ("onvif", "hardware_id", "HW-1") in observed


def test_onvif_rtsp_flow_submits_rtsp_observations_to_oads():
    plugin = ONVIFPlugin()
    state = AnalysisState()
    pkt = (
        Ether(src="66:77:88:99:aa:bb", dst="00:11:22:33:44:55")
        / IP(src="172.22.10.251", dst="172.22.10.203")
        / TCP(sport=554, dport=53196)
        / Raw(
            load=(
                b"RTSP/1.0 200 OK\r\n"
                b"Server: Live555 Streaming Media\r\n"
                b"Session: abc123\r\n"
                b"User-Agent: ignored-on-response\r\n"
                b"\r\n"
            )
        )
    )

    assert plugin.match(pkt)
    plugin.process(pkt, state)

    payload = build_observations_payload(state, "capture")
    observed = {
        (obs["protocol"], obs["field"], obs["value"])
        for obs in payload["observations"]
    }

    assert ("rtsp", "media_type", "video") in observed
    assert ("rtsp", "server", "Live555 Streaming Media") in observed
    assert ("rtsp", "session", "abc123") in observed

    for obs in payload["observations"]:
        if obs["protocol"] == "rtsp" and obs["field"] == "server":
            assert obs["ip"] == "172.22.10.251"
            assert obs["raw_context"]["source_port"] == 554
            assert obs["raw_context"]["destination_port"] == 53196
