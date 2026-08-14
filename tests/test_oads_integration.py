import json
import urllib.error

from guppy_ics.core.state import AnalysisState
from guppy_ics.integrations.oads import (
    OADSClient,
    attach_oads_profiles,
    build_observations_payload,
    debug_payload_preview,
    filter_payload_for_unknown_oads_assets,
    submit_observations_in_batches,
    submit_observations_to_oads,
)


def test_payload_conversion_uses_passive_raw_fields_only():
    state = AnalysisState()
    asset_id = state.register_asset(
        "aa:bb:cc:dd:ee:ff",
        protocol="profinet",
        vendor="Inferred Vendor",
        metadata={
            "station_name": "plc-1",
            "vendor": "do-not-send",
            "model": "do-not-send",
            "identity_links": {("aa:bb:cc:dd:ee:ff", "192.168.1.10", "l2_l3_observed")},
        },
        evidence_layer="l2",
    )
    state.link_identifiers("aa:bb:cc:dd:ee:ff", "192.168.1.10", protocol="profinet")
    state.assets[asset_id]["identifiers"]["hostname"] = {"plc-1.local"}
    state.register_communication(
        src="192.168.1.10",
        dst="192.168.1.20",
        protocol="profinet",
        function="dcp",
        metadata={"dst_port": 34962, "vendor": "do-not-send", "manufacturer_id": "0x002a"},
    )

    payload = build_observations_payload(state, "capture-1")

    assert payload["source"] == "guppy-ics"
    assert payload["capture_id"] == "capture-1"

    observed = {(obs["field"], obs["value"]) for obs in payload["observations"]}
    fields = {obs["field"] for obs in payload["observations"]}
    assert ("mac", "aa:bb:cc:dd:ee:ff") in observed
    assert ("ip", "192.168.1.10") in observed
    assert ("hostname", "plc-1.local") in observed
    assert ("station_name", "plc-1") in observed
    assert ("observed_protocol", "profinet") in observed
    assert ("protocol_function", "dcp") in observed
    assert ("manufacturer_id", "0x002a") in observed
    assert "vendor" not in fields
    assert "model" not in fields


def test_client_sends_expected_headers_and_body_without_auth(monkeypatch):
    captured = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return b'{"ok": true}'

    def fake_urlopen(req, timeout):
        captured["url"] = req.full_url
        captured["method"] = req.get_method()
        captured["headers"] = dict(req.headers)
        captured["content_type"] = req.headers["Content-type"]
        captured["body"] = json.loads(req.data.decode("utf-8"))
        captured["timeout"] = timeout
        return Response()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    client = OADSClient("http://oads.local/", timeout=3.0)
    result = client.submit_observations({"observations": []})

    assert result == {"ok": True}
    assert captured["url"] == "http://oads.local/api/v1/observations"
    assert captured["method"] == "POST"
    assert "X-api-key" not in captured["headers"]
    assert captured["content_type"] == "application/json"
    assert captured["body"] == {"observations": []}
    assert captured["timeout"] == 3.0


def test_client_get_assets_sends_no_auth_header(monkeypatch):
    captured = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return b"[]"

    def fake_urlopen(req, timeout):
        captured["headers"] = dict(req.headers)
        return Response()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    client = OADSClient("http://localhost:8000")
    assert client.get_assets() == []
    assert "X-api-key" not in captured["headers"]


def test_oads_outage_does_not_crash_analysis(capsys):
    class FailingClient:
        def submit_observations(self, payload):
            raise urllib.error.URLError("down")

    state = AnalysisState()
    state.register_asset("192.168.1.10", protocol="modbus")

    result = submit_observations_to_oads(state, "capture-1", FailingClient())

    assert result is None
    assert "WARNING: OADS observation submit failed" in capsys.readouterr().out


def test_enriched_asset_matching_prefers_mac_then_ip():
    state = AnalysisState()
    mac_asset = state.register_asset("aa:bb:cc:dd:ee:ff", protocol="modbus")
    state.link_identifiers("aa:bb:cc:dd:ee:ff", "192.168.1.10", protocol="modbus")
    ip_asset = state.register_asset("192.168.1.20", protocol="opcua")

    matched = attach_oads_profiles(
        state,
        [
            {"asset_id": "ip-profile", "ip": "192.168.1.10"},
            {"asset_id": "mac-profile", "mac": "AA:BB:CC:DD:EE:FF"},
            {"asset_id": "second", "identifiers": {"ip": {"192.168.1.20"}}},
        ],
    )

    assert matched == 2
    assert state.assets[mac_asset]["oads_profile"]["asset_id"] == "mac-profile"
    assert state.assets[ip_asset]["oads_profile"]["asset_id"] == "second"


def test_enriched_asset_matching_accepts_common_oads_identifier_shapes():
    state = AnalysisState()
    mac_asset = state.register_asset("aa:bb:cc:dd:ee:ff", protocol="modbus")
    ip_asset = state.register_asset("192.168.1.30", protocol="opcua")

    matched = attach_oads_profiles(
        state,
        [
            {
                "asset_id": "nested-mac",
                "network_interfaces": [{"mac_address": "AA:BB:CC:DD:EE:FF"}],
            },
            {
                "asset_id": "identifier-ip",
                "identifiers": [{"type": "ip_address", "value": "192.168.1.30"}],
            },
        ],
    )

    assert matched == 2
    assert state.assets[mac_asset]["oads_profile"]["asset_id"] == "nested-mac"
    assert state.assets[ip_asset]["oads_profile"]["asset_id"] == "identifier-ip"


def test_enriched_asset_matching_accepts_documented_oads_asset_shape():
    state = AnalysisState()
    asset_id = state.register_asset("00:1B:1B:12:34:56", protocol="s7comm")
    state.link_identifiers("00:1B:1B:12:34:56", "192.168.10.20", protocol="s7comm")

    matched = attach_oads_profiles(
        state,
        [
            {
                "asset_id": "oads-asset",
                "primary_mac": "00:1B:1B:12:34:56",
                "ips": ["192.168.10.20"],
                "vendor": "Siemens",
                "model": "CPU1515-2 PN",
            },
        ],
    )

    assert matched == 1
    assert state.assets[asset_id]["oads_profile"]["model"] == "CPU1515-2 PN"


def test_debug_payload_preview_is_json_and_truncated():
    preview = debug_payload_preview({"response": "x" * 50}, max_chars=30)

    assert '"response"' in preview
    assert "truncated" in preview


def test_payload_filter_skips_observations_for_assets_already_known_to_oads():
    payload = {
        "source": "guppy-ics",
        "capture_id": "capture-1",
        "observations": [
            {"mac": "AA:BB:CC:DD:EE:FF", "ip": "192.168.1.10", "protocol": "modbus", "field": "mac", "value": "AA"},
            {"mac": "00:11:22:33:44:55", "ip": "192.168.1.20", "protocol": "dhcp", "field": "hostname", "value": "new"},
        ],
    }

    filtered, skipped = filter_payload_for_unknown_oads_assets(
        payload,
        [{"primary_mac": "aa:bb:cc:dd:ee:ff", "ips": ["192.168.1.10"]}],
    )

    assert skipped == 1
    assert filtered["observations"] == [payload["observations"][1]]


def test_batched_submit_stops_after_first_failed_batch():
    class Client:
        def __init__(self):
            self.calls = 0

        def submit_observations(self, payload):
            self.calls += 1
            if self.calls == 2:
                raise TimeoutError("slow")
            return {"accepted": len(payload["observations"])}

    payload = {"source": "guppy-ics", "capture_id": "capture-1", "observations": [{"field": str(i)} for i in range(5)]}

    result = submit_observations_in_batches(Client(), payload, batch_size=2)

    assert result["submitted"] is True
    assert result["submitted_observations"] == 2
    assert result["failed"] is True
    assert result["error"] == "slow"
