from guppy_ics.core.communications import filter_communications_for_presentation


def test_specific_protocol_suppresses_reverse_generic_transport_for_same_service_port():
    communications = [
        {
            "src_asset_id": "client",
            "dst_asset_id": "plc",
            "protocol": "modbus",
            "function": "client -> server",
            "metadata": {"src_port": 53136, "dst_port": 502},
        },
        {
            "src_asset_id": "plc",
            "dst_asset_id": "client",
            "protocol": "tcp",
            "metadata": {"src_port": 502, "dst_port": 51801},
        },
    ]

    filtered = filter_communications_for_presentation(communications)

    assert [comm["protocol"] for comm in filtered] == ["modbus"]


def test_generic_transport_remains_when_no_specific_protocol_exists():
    communications = [
        {
            "src_asset_id": "host-a",
            "dst_asset_id": "host-b",
            "protocol": "tcp",
            "metadata": {"src_port": 50000, "dst_port": 443},
        },
    ]

    filtered = filter_communications_for_presentation(communications)

    assert filtered == communications
