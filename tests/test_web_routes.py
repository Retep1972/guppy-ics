from starlette.requests import Request

from guppy_ics.core.state import AnalysisState
from guppy_ics.web.app import index
from guppy_ics.web.routes.help import help_page
from guppy_ics.web.routes.upload import _analysis_results, upload_page, view_segmentation_report


def _request(path="/"):
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": path,
            "headers": [],
            "query_string": b"",
            "server": ("testserver", 80),
            "scheme": "http",
            "client": ("testclient", 1),
        }
    )


def test_index_route_renders_without_template_response_signature_error():
    response = index(_request("/"))

    assert response.status_code == 200
    assert b"Upload PCAP" in response.body


def test_upload_route_renders_without_template_response_signature_error():
    response = upload_page(_request("/upload"))

    assert response.status_code == 200
    assert b"Upload" in response.body


def test_help_route_renders_without_template_response_signature_error():
    response = help_page(_request("/help"))

    assert response.status_code == 200
    assert b"Guppy" in response.body
    assert b"Segmentation Assessment" in response.body


def test_segmentation_report_route_renders_download_action():
    state = AnalysisState()
    state.register_asset("10.10.10.10", role="engineering workstation")
    state.register_asset("10.10.10.20", role="plc", protocol="s7comm")
    state.register_communication(
        src="10.10.10.10",
        dst="10.10.10.20",
        protocol="s7comm",
        metadata={"transport": "tcp", "dst_port": 102},
    )
    bus_id = "segmentation-test"
    _analysis_results[bus_id] = state
    try:
        response = view_segmentation_report(bus_id)
    finally:
        _analysis_results.pop(bus_id, None)

    assert response.status_code == 200
    assert b"Download segmentation assessment" in response.body
    assert b"SEGMENTATION" in response.body.upper()
