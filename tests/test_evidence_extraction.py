from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from guppy_ics.core.state import AnalysisState
from guppy_ics.integrations.oads import build_observations_payload
from guppy_ics.protocols.discovery import DiscoveryEvidencePlugin
from guppy_ics.protocols.l2l3 import L2L3LinkerPlugin
from guppy_ics.protocols.transport import TransportPlugin


def _process(packet, state, *plugins):
    for plugin in plugins:
        if plugin.match(packet):
            plugin.process(packet, state)


def test_multiple_vmware_macs_on_same_subnet_are_not_merged():
    state = AnalysisState()
    linker = L2L3LinkerPlugin()
    packets = [
        Ether(src="00:0c:29:61:e9:9b", dst="ff:ff:ff:ff:ff:ff")
        / IP(src="172.27.224.10", dst="255.255.255.255")
        / UDP(sport=49152, dport=3702),
        Ether(src="00:0c:29:8e:b8:c7", dst="01:00:5e:00:00:fc")
        / IP(src="172.27.224.70", dst="224.0.0.252")
        / UDP(sport=5355, dport=5355),
        Ether(src="00:0c:29:9d:9e:9e", dst="01:00:5e:7f:ff:fa")
        / IP(src="172.27.224.80", dst="239.255.255.250")
        / UDP(sport=64381, dport=1900),
    ]

    for packet in packets:
        _process(packet, state, linker)

    mac_assets = {state.asset_index[mac] for mac in (
        "00:0c:29:61:e9:9b",
        "00:0c:29:8e:b8:c7",
        "00:0c:29:9d:9e:9e",
    )}

    assert len(mac_assets) == 3


def test_broadcast_and_multicast_destinations_do_not_become_assets():
    state = AnalysisState()
    transport = TransportPlugin()
    pkt = (
        Ether(src="00:0c:29:9d:9e:9e", dst="ff:ff:ff:ff:ff:ff")
        / IP(src="172.27.224.70", dst="255.255.255.255")
        / UDP(sport=64381, dport=1947)
    )

    _process(pkt, state, L2L3LinkerPlugin(), transport)

    assert "255.255.255.255" not in state.asset_index
    assert state.special_addresses["255.255.255.255"]["classification"] == "limited_broadcast"
    evidence = state.evidence[0]
    assert evidence["type"] == "udp_service_observation"
    assert evidence["attributes"]["dst_port"] == 1947
    assert evidence["attributes"]["scope"] == "broadcast"


def test_dhcp_hostname_vendor_and_requested_ip_evidence():
    state = AnalysisState()
    discovery = DiscoveryEvidencePlugin()
    pkt = (
        Ether(src="00:0c:29:e6:14:21", dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=bytes.fromhex("000c29e61421"), xid=1)
        / DHCP(
            options=[
                ("message-type", "discover"),
                ("hostname", b"kali02163"),
                ("vendor_class_id", b"MSFT 5.0"),
                ("requested_addr", "172.27.224.71"),
                ("param_req_list", [1, 3, 6, 15]),
                "end",
            ]
        )
    )

    _process(pkt, state, discovery)

    asset_id = state.asset_index["00:0c:29:e6:14:21"]
    assert state.asset_index["172.27.224.71"] == asset_id
    assert "kali02163" in state.assets[asset_id]["identifiers"]["hostname"]
    evidence = next(item for item in state.evidence if item["type"] == "dhcp")
    assert evidence["attributes"]["hostname"] == "kali02163"
    assert evidence["attributes"]["vendor_class"] == "MSFT 5.0"
    assert evidence["attributes"]["parameter_request_list"] == [1, 3, 6, 15]


def test_llmnr_query_is_evidence_not_hostname_claim():
    state = AnalysisState()
    packet = (
        Ether(src="00:0c:29:8e:b8:c7", dst="01:00:5e:00:00:fc")
        / IP(src="172.27.224.70", dst="224.0.0.252")
        / UDP(sport=5355, dport=5355)
        / DNS(rd=0, qd=DNSQR(qname="isatap.local", qtype="A"))
    )

    _process(packet, state, L2L3LinkerPlugin(), DiscoveryEvidencePlugin())

    asset_id = state.asset_index["172.27.224.70"]
    assert "hostname" not in state.assets[asset_id]["identifiers"]
    evidence = next(item for item in state.evidence if item["type"] == "llmnr")
    assert evidence["attributes"]["queries"][0]["name"] == "isatap.local"
    assert evidence["attributes"]["scope"] == "multicast"


def test_dns_response_records_are_preserved():
    state = AnalysisState()
    packet = (
        Ether(src="00:11:22:33:44:55", dst="00:0c:29:8e:b8:c7")
        / IP(src="192.168.1.1", dst="172.27.224.70")
        / UDP(sport=53, dport=53000)
        / DNS(qr=1, an=DNSRR(rrname="plc.local", type="A", rdata="192.168.1.50"), ancount=1)
    )

    _process(packet, state, L2L3LinkerPlugin(), DiscoveryEvidencePlugin())

    evidence = next(item for item in state.evidence if item["type"] == "dns")
    assert evidence["attributes"]["answers"][0]["name"] == "plc.local"
    assert evidence["attributes"]["answers"][0]["rdata"] == "192.168.1.50"


def test_ssdp_and_ws_discovery_fields_are_extracted():
    state = AnalysisState()
    plugin = DiscoveryEvidencePlugin()
    ssdp = (
        Ether(src="00:0c:29:9d:9e:9e", dst="01:00:5e:7f:ff:fa")
        / IP(src="172.27.224.70", dst="239.255.255.250")
        / UDP(sport=64381, dport=1900)
        / Raw(b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nST: ssdp:all\r\n\r\n")
    )
    ws = (
        Ether(src="00:0c:29:8e:b8:c7", dst="01:00:5e:7f:ff:fa")
        / IP(src="172.27.224.70", dst="239.255.255.250")
        / UDP(sport=49152, dport=3702)
        / Raw(
            b"<s:Envelope><s:Header><a:MessageID>uuid:1</a:MessageID></s:Header>"
            b"<s:Body><d:ProbeMatches><d:ProbeMatch><d:Types>wsdp:Device pub:Computer</d:Types>"
            b"<d:XAddrs>http://172.27.224.70:5357/</d:XAddrs></d:ProbeMatch></d:ProbeMatches></s:Body></s:Envelope>"
        )
    )

    _process(ssdp, state, L2L3LinkerPlugin(), plugin)
    _process(ws, state, L2L3LinkerPlugin(), plugin)

    ssdp_evidence = next(item for item in state.evidence if item["type"] == "ssdp")
    ws_evidence = next(item for item in state.evidence if item["type"] == "ws_discovery")
    assert ssdp_evidence["attributes"]["st"] == "ssdp:all"
    assert ws_evidence["attributes"]["types"] == ["wsdp:Device pub:Computer"]
    assert ws_evidence["attributes"]["xaddrs"] == ["http://172.27.224.70:5357/"]


def test_evidence_is_serialized_to_oads_observations():
    state = AnalysisState()
    packet = (
        Ether(src="00:0c:29:e6:14:21", dst="ff:ff:ff:ff:ff:ff")
        / IP(src="172.27.224.70", dst="255.255.255.255")
        / UDP(sport=64381, dport=1947)
    )
    _process(packet, state, L2L3LinkerPlugin(), TransportPlugin())

    payload = build_observations_payload(state, "capture-1")
    observed = {(obs["protocol"], obs["field"], obs["value"]) for obs in payload["observations"]}

    assert ("udp", "evidence_type", "udp_service_observation") in observed
    assert ("udp", "dst_port", "1947") in observed
    assert ("udp", "scope", "broadcast") in observed


def test_oads_service_observations_are_compacted_by_asset_port_and_scope():
    state = AnalysisState()
    linker = L2L3LinkerPlugin()
    transport = TransportPlugin()

    for sport in range(64000, 64020):
        packet = (
            Ether(src="00:0c:29:e6:14:21", dst="ff:ff:ff:ff:ff:ff")
            / IP(src="172.27.224.70", dst="255.255.255.255")
            / UDP(sport=sport, dport=1947)
        )
        _process(packet, state, linker, transport)

    payload = build_observations_payload(state, "capture-1")
    service_observations = [
        obs
        for obs in payload["observations"]
        if obs["protocol"] == "udp" and obs["field"] == "evidence_type"
    ]

    assert len(state.evidence) == 20
    assert len(service_observations) == 1
