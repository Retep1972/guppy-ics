from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from guppy_ics.core.state import AnalysisState
from guppy_ics.protocols.opcua import OPCUAPlugin


def test_opcua_is_detected_on_non_standard_port_by_uatcp_header():
    packet = (
        Ether(src="00:0c:29:a0:86:e6", dst="00:50:8d:9a:08:5e")
        / IP(src="192.168.41.176", dst="192.168.41.212")
        / TCP(sport=58674, dport=12001)
        / Raw(b"HELF\x20\x00\x00\x00opc.tcp://192.168.41.212:12001")
    )
    state = AnalysisState()
    plugin = OPCUAPlugin()

    assert plugin.match(packet)
    plugin.process(packet, state)

    protocols = {protocol for asset in state.assets.values() for protocol in asset.get("protocols", set())}
    assert "opcua" in protocols
    comm = next(iter(state.communications.values()))
    assert comm["protocol"] == "opcua"
    assert comm["function"] == "request"
    assert comm["metadata"]["server_port"] == 12001
    assert comm["metadata"]["message_type"] == "HEL"


def test_non_opcua_payload_on_non_standard_port_is_not_detected():
    packet = (
        Ether()
        / IP(src="192.168.41.176", dst="192.168.41.212")
        / TCP(sport=58674, dport=12001)
        / Raw(b"GET / HTTP/1.1\r\n\r\n")
    )

    assert not OPCUAPlugin().match(packet)
