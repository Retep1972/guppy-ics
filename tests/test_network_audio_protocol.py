from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from guppy_ics.core.state import AnalysisState
from guppy_ics.integrations.oads import build_observations_payload
from guppy_ics.protocols.network_audio import NetworkAudioPlugin, parse_sdp, parse_sip_message


def _udp_packet(src, dst, sport, dport, payload: bytes):
    return (
        Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02")
        / IP(src=src, dst=dst)
        / UDP(sport=sport, dport=dport)
        / Raw(payload)
    )


def _rtp(seq: int, *, ssrc: int = 0x12345678, payload_type: int = 8):
    return (
        bytes([0x80, payload_type])
        + seq.to_bytes(2, "big")
        + (160 * seq).to_bytes(4, "big")
        + ssrc.to_bytes(4, "big")
        + b"\x00" * 20
    )


def test_sip_register_extracts_identity_agent_and_realm_without_credentials():
    raw = (
        b"REGISTER sip:172.20.10.5 SIP/2.0\r\n"
        b"From: <sip:1004@172.20.10.5>\r\n"
        b"To: <sip:1004@172.20.10.5>\r\n"
        b"Contact: <sip:1004@172.20.10.21>\r\n"
        b"Call-ID: reg-1\r\n"
        b"CSeq: 1 REGISTER\r\n"
        b"User-Agent: Example Intercom 4.2\r\n"
        b'Authorization: Digest username="1004", realm="pa.local", response="SECRET"\r\n'
        b"Content-Length: 0\r\n\r\n"
    )
    state = AnalysisState()
    plugin = NetworkAudioPlugin()
    packet = _udp_packet("172.20.10.21", "172.20.10.5", 5062, 5060, raw)

    assert plugin.match(packet)
    plugin.process(packet, state)

    evidence = [item for item in state.evidence if item["type"] == "sip_message"][0]
    attrs = evidence["attributes"]
    assert attrs["method"] == "REGISTER"
    assert attrs["from_user"] == "1004"
    assert attrs["from_host"] == "172.20.10.5"
    assert attrs["user_agent"] == "Example Intercom 4.2"
    assert attrs["authorization_realm"] == "pa.local"
    assert "SECRET" not in str(attrs)
    assert any(item["type"] == "sip_registration" for item in state.evidence)


def test_sip_invite_with_sdp_extracts_multicast_audio_media():
    raw = (
        b"INVITE sip:zone1@172.20.10.21 SIP/2.0\r\n"
        b"From: <sip:controller@172.20.10.10>\r\n"
        b"To: <sip:zone1@172.20.10.21>\r\n"
        b"Call-ID: call-1\r\n"
        b"CSeq: 2 INVITE\r\n"
        b"Content-Type: application/sdp\r\n"
        b"Content-Length: 160\r\n\r\n"
        b"v=0\r\n"
        b"o=- 1 1 IN IP4 172.20.10.10\r\n"
        b"s=Paging\r\n"
        b"c=IN IP4 239.10.20.5\r\n"
        b"t=0 0\r\n"
        b"m=audio 5004 RTP/AVP 0 8 96\r\n"
        b"a=rtpmap:0 PCMU/8000\r\n"
        b"a=rtpmap:8 PCMA/8000\r\n"
        b"a=rtpmap:96 opus/48000/2\r\n"
        b"a=sendonly\r\n"
    )
    state = AnalysisState()
    plugin = NetworkAudioPlugin()
    packet = _udp_packet("172.20.10.10", "172.20.10.21", 5060, 5060, raw)

    plugin.process(packet, state)

    media = [item for item in state.evidence if item["type"] == "sdp_media"][0]["attributes"]
    assert media["media_type"] == "audio"
    assert media["destination_ip"] == "239.10.20.5"
    assert media["destination_port"] == 5004
    assert media["scope"] == "multicast"
    assert {"payload_type": 96, "name": "opus", "clock_rate": 48000, "channels": 2} in media["codecs"]
    assert "239.10.20.5" in state.special_addresses


def test_sip_response_extracts_status_and_server():
    parsed = parse_sip_message(
        b"SIP/2.0 200 OK\r\n"
        b"Call-ID: call-1\r\n"
        b"CSeq: 2 INVITE\r\n"
        b"Server: Example SIP Server\r\n"
        b"Content-Length: 0\r\n\r\n"
    )

    assert parsed["status_code"] == 200
    assert parsed["reason_phrase"] == "OK"
    assert parsed["server"] == "Example SIP Server"


def test_sdp_unicast_and_srtp_flags():
    sdp = parse_sdp(
        "v=0\r\n"
        "c=IN IP4 172.20.10.22\r\n"
        "m=audio 6000 RTP/SAVP 96\r\n"
        "a=rtpmap:96 L16/48000/2\r\n"
        "a=recvonly\r\n"
    )

    media = sdp["media"][0]
    assert media["scope"] == "unicast"
    assert media["transport"] == "RTP/SAVP"
    assert media["direction"] == "recvonly"


def test_rtp_requires_multiple_consistent_packets_and_does_not_make_multicast_asset():
    state = AnalysisState()
    plugin = NetworkAudioPlugin()

    plugin.process(_udp_packet("172.20.10.10", "239.10.20.5", 4000, 5004, _rtp(1)), state)
    assert not [item for item in state.evidence if item["type"] == "rtp_stream"]

    plugin.process(_udp_packet("172.20.10.10", "239.10.20.5", 4000, 5004, _rtp(2)), state)
    rtp = [item for item in state.evidence if item["type"] == "rtp_stream"][0]["attributes"]
    assert rtp["packet_count"] == 2
    assert rtp["ssrc"] == 0x12345678
    assert rtp["scope"] == "multicast"
    assert "239.10.20.5" in state.special_addresses
    assert "239.10.20.5" not in state.asset_index


def test_random_udp_is_not_rtp():
    packet = _udp_packet("172.20.10.10", "172.20.10.21", 4000, 5004, b"not rtp")
    assert not NetworkAudioPlugin().match(packet)


def test_rtcp_sender_report_is_evidence():
    payload = b"\x80\xc8\x00\x06" + (0x12345678).to_bytes(4, "big") + b"\x00" * 24
    state = AnalysisState()
    plugin = NetworkAudioPlugin()

    plugin.process(_udp_packet("172.20.10.10", "239.10.20.5", 5005, 5005, payload), state)

    rtcp = [item for item in state.evidence if item["type"] == "rtcp_stream"][0]["attributes"]
    assert rtcp["packet_type"] == "sender_report"
    assert rtcp["ssrc"] == 0x12345678


def test_igmp_join_and_leave_create_membership_evidence_without_group_asset():
    state = AnalysisState()
    plugin = NetworkAudioPlugin()
    join = Ether(src="00:00:00:00:00:21") / IP(src="172.20.10.21", dst="224.0.0.22", proto=2) / Raw(
        b"\x16\x00\x00\x00\xef\x0a\x14\x05"
    )
    leave = Ether(src="00:00:00:00:00:21") / IP(src="172.20.10.21", dst="224.0.0.2", proto=2) / Raw(
        b"\x17\x00\x00\x00\xef\x0a\x14\x05"
    )

    assert plugin.match(join)
    plugin.process(join, state)
    plugin.process(leave, state)

    events = [item["attributes"]["event"] for item in state.evidence if item["type"] == "igmp_membership"]
    assert "membership_report" in events
    assert "leave_group" in events
    assert "239.10.20.5" in state.special_addresses
    assert "239.10.20.5" not in state.asset_index


def test_ptp_observation_extracts_clock_identity():
    payload = bytearray(44)
    payload[0] = 0x0B
    payload[1] = 0x02
    payload[4] = 0
    payload[20:28] = bytes.fromhex("0011223344556677")
    payload[28:30] = (1).to_bytes(2, "big")
    payload[30:32] = (9).to_bytes(2, "big")
    state = AnalysisState()
    plugin = NetworkAudioPlugin()

    plugin.process(_udp_packet("172.20.10.10", "224.0.1.129", 320, 320, bytes(payload)), state)

    ptp = [item for item in state.evidence if item["type"] == "ptp_observation"][0]["attributes"]
    assert ptp["message_type"] == "announce"
    assert ptp["clock_identity"] == "00:11:22:33:44:55:66:77"


def test_sip_sdp_rtp_correlation_and_oads_serialization():
    state = AnalysisState()
    plugin = NetworkAudioPlugin()
    invite = (
        b"INVITE sip:zone@172.20.10.21 SIP/2.0\r\n"
        b"Call-ID: call-rtp\r\n"
        b"Content-Type: application/sdp\r\n\r\n"
        b"v=0\r\nc=IN IP4 239.10.20.5\r\nm=audio 5004 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\n"
    )
    plugin.process(_udp_packet("172.20.10.10", "172.20.10.21", 5060, 5060, invite), state)
    plugin.process(_udp_packet("172.20.10.10", "239.10.20.5", 4000, 5004, _rtp(1)), state)
    plugin.process(_udp_packet("172.20.10.10", "239.10.20.5", 4000, 5004, _rtp(2)), state)

    assert any(item["type"] == "multicast_media_group" for item in state.evidence)
    payload = build_observations_payload(state, "audio-fixture")
    fields = {(obs["protocol"], obs["field"]) for obs in payload["observations"]}
    assert ("sip", "call_id") in fields
    assert ("rtp", "ssrc") in fields
    assert ("sdp", "destination_ip") not in fields
    assert not any(
        obs["field"] in {"destination_ip", "dst_ip", "group"} and obs["value"] == "239.10.20.5"
        for obs in payload["observations"]
    )
    assert any(
        obs["protocol"] == "sdp"
        and obs["field"] == "evidence_type"
        and obs["raw_context"]["evidence_attributes"]["destination_ip"] == "239.10.20.5"
        for obs in payload["observations"]
    )


def test_malformed_sip_and_rtp_do_not_crash():
    state = AnalysisState()
    plugin = NetworkAudioPlugin()

    plugin.process(_udp_packet("172.20.10.10", "172.20.10.21", 5060, 5060, b"INVITE bad"), state)
    plugin.process(_udp_packet("172.20.10.10", "172.20.10.21", 4000, 5004, b"\x80"), state)

    assert state.evidence == []
