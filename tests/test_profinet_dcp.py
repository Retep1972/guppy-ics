from scapy.layers.l2 import Ether
from scapy.packet import Raw

from guppy_ics.core.state import AnalysisState
from guppy_ics.integrations.oads import build_observations_payload
from guppy_ics.protocols.profinet import ProfinetPlugin


def test_profinet_dcp_station_name_starts_after_data_length_field():
    payload = (
        b"\xfe\xfe"  # frame id
        b"\x05\x00"  # service id/type
        b"\x00\x00\x00\x01"  # xid
        b"\x00\x01"  # response delay
        b"\x00\x0c"  # DCP data length
        b"\x02\x02\x00\x07switch3"  # device properties / station name
        b"\x00"  # padding
    )
    packet = (
        Ether(src="00:1b:1b:02:9a:c3", dst="01:0e:cf:00:00:00", type=0x8892)
        / Raw(payload)
    )
    state = AnalysisState()
    plugin = ProfinetPlugin()

    assert plugin.match(packet)
    plugin.process(packet, state)

    asset = state.assets[state.asset_index["00:1b:1b:02:9a:c3"]]
    assert asset["metadata"]["station_name"] == "switch3"

    payload = build_observations_payload(state, "capture-1")
    observed = {(obs["protocol"], obs["field"], obs["value"]) for obs in payload["observations"]}
    assert ("profinet", "station_name", "switch3") in observed
