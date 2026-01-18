from guppy_ics.core.state import AnalysisState


def test_basic_state():
    state = AnalysisState()

    a = state.register_asset("192.168.1.10", role="client", protocol="modbus")
    b = state.register_asset("192.168.1.20", role="plc", protocol="modbus")

    state.register_communication(
        src_ip="192.168.1.10",
        dst_ip="192.168.1.20",
        protocol="modbus",
        function="read_holding_registers"
    )

    summary = state.summary()

    assert summary["assets"] == 2
    assert summary["communications"] == 1
