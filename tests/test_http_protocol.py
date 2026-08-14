from scapy.all import Ether, IP, TCP, Raw

from guppy_ics.core.state import AnalysisState
from guppy_ics.integrations.oads import build_observations_payload
from guppy_ics.protocols.http import HTTPPlugin
from guppy_ics.protocols.registry import available_protocols, load_plugins


def test_http_response_headers_and_title_are_submitted_to_oads():
    plugin = HTTPPlugin()
    state = AnalysisState()
    pkt = (
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        / IP(src="192.168.10.20", dst="192.168.10.5")
        / TCP(sport=80, dport=53100)
        / Raw(
            load=(
                b"HTTP/1.1 200 OK\r\n"
                b"Server: SIMATIC HMI HTTP Server\r\n"
                b"WWW-Authenticate: Basic realm=\"PLC\"\r\n"
                b"Location: /index.html\r\n"
                b"\r\n"
                b"<html><title>PLC Web UI</title></html>"
            )
        )
    )

    assert plugin.match(pkt)
    plugin.process(pkt, state)

    payload = build_observations_payload(state, "capture")
    observed = {
        (obs["ip"], obs["protocol"], obs["field"], obs["value"])
        for obs in payload["observations"]
    }

    assert ("192.168.10.20", "http", "server", "SIMATIC HMI HTTP Server") in observed
    assert ("192.168.10.20", "http", "www_authenticate", 'Basic realm="PLC"') in observed
    assert ("192.168.10.20", "http", "location", "/index.html") in observed
    assert ("192.168.10.20", "http", "title", "PLC Web UI") in observed


def test_http_request_user_agent_is_submitted_for_client_asset():
    plugin = HTTPPlugin()
    state = AnalysisState()
    pkt = (
        Ether(src="66:77:88:99:aa:bb", dst="00:11:22:33:44:55")
        / IP(src="192.168.10.5", dst="192.168.10.20")
        / TCP(sport=53100, dport=80)
        / Raw(load=b"GET / HTTP/1.1\r\nUser-Agent: CameraClient/1.0\r\n\r\n")
    )

    assert plugin.match(pkt)
    plugin.process(pkt, state)

    payload = build_observations_payload(state, "capture")
    observed = {
        (obs["ip"], obs["protocol"], obs["field"], obs["value"])
        for obs in payload["observations"]
    }

    assert ("192.168.10.5", "http", "user_agent", "CameraClient/1.0") in observed


def test_http_is_available_and_default_loaded():
    available_protocol_map = {proto["slug"]: proto for proto in available_protocols()}
    safe_default_loaded = {plugin.slug for plugin in load_plugins(enabled=[])}

    assert available_protocol_map["http"]["safe_by_default"] is True
    assert "http" in safe_default_loaded
