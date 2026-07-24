from starlette.requests import Request

from guppy_ics.core.state import AnalysisState
from guppy_ics.web.deps import templates
from guppy_ics.web.routes.upload import run_oads_enrichment


def _request():
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/upload/result",
            "headers": [],
            "query_string": b"bus_id=test",
            "server": ("testserver", 80),
            "scheme": "http",
            "client": ("testclient", 1),
        }
    )


def test_missing_oads_config_status_renders_result_template():
    state = AnalysisState()
    state.register_asset("192.168.1.10", protocol="modbus")

    status = run_oads_enrichment(
        state,
        capture_id="capture",
        enabled=True,
        base_url="",
    )

    response = templates.TemplateResponse(
        "upload_result.html",
        {
            "request": _request(),
            "summary": state.summary(),
            "assets": [],
            "communications": [],
            "topology": {},
            "oads_status": status,
        },
    )

    assert response.status_code == 200
    assert b"OADS details" in response.body
