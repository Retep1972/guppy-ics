from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional


SAFE_ASSET_METADATA_FIELDS = {
    "station_name",
    "hostname",
    "sysObjectID",
    "manufacturer_id",
    "vendor_id",
    "order_number",
    "firmware_version",
}

SAFE_COMM_METADATA_FIELDS = {
    "src_port",
    "dst_port",
    "transport",
    "frame_id",
    "identifier_type",
    "manufacturer_id",
    "vendor_id",
}


@dataclass
class OADSClient:
    base_url: str
    timeout: float = 5.0

    def __post_init__(self) -> None:
        self.base_url = self.base_url.rstrip("/")

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[Dict[str, Any]] = None,
    ) -> Any:
        data = None
        headers = {
            "Accept": "application/json",
        }
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(
            f"{self.base_url}{path}",
            data=data,
            headers=headers,
            method=method,
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            payload = resp.read()
            if not payload:
                return None
            return json.loads(payload.decode("utf-8"))

    def submit_observations(self, payload: Dict[str, Any]) -> Any:
        return self._request("POST", "/api/v1/observations", payload)

    def get_assets(self) -> Any:
        return self._request("GET", "/api/v1/assets")

    def get_asset(self, asset_id: str) -> Any:
        return self._request("GET", f"/api/v1/assets/{asset_id}")

    def health(self) -> Any:
        return self._request("GET", "/health")


def build_observations_payload(state: Any, capture_id: str) -> Dict[str, Any]:
    observations: List[Dict[str, Any]] = []

    for asset_id, asset in _iter_assets(state):
        protocols = sorted(asset.get("protocols", set()) or [])
        default_protocol = protocols[0] if protocols else "unknown"

        for id_type in ("mac", "ip", "hostname"):
            for value in _iter_values(asset.get("identifiers", {}).get(id_type)):
                observations.append(
                    _observation(
                        asset=asset,
                        asset_id=asset_id,
                        protocol=default_protocol,
                        field=id_type,
                        value=value,
                    )
                )

        for protocol in protocols:
            observations.append(
                _observation(
                    asset=asset,
                    asset_id=asset_id,
                    protocol=protocol,
                    field="observed_protocol",
                    value=protocol,
                )
            )

        metadata = asset.get("metadata", {}) or {}
        for field in sorted(SAFE_ASSET_METADATA_FIELDS):
            if field in metadata:
                observations.append(
                    _observation(
                        asset=asset,
                        asset_id=asset_id,
                        protocol=default_protocol,
                        field=field,
                        value=metadata[field],
                    )
                )

        for link in _iter_values(metadata.get("identity_links")):
            observations.append(
                _observation(
                    asset=asset,
                    asset_id=asset_id,
                    protocol=default_protocol,
                    field="identity_link",
                    value=_stringify(link),
                )
            )

    for comm in _iter_comms(state):
        protocol = comm.get("protocol") or "unknown"
        for endpoint in ("src_asset_id", "dst_asset_id"):
            asset_id = comm.get(endpoint)
            asset = getattr(state, "assets", {}).get(asset_id, {})
            if not asset:
                continue

            function = comm.get("function")
            if function:
                observations.append(
                    _observation(
                        asset=asset,
                        asset_id=asset_id,
                        protocol=protocol,
                        field="protocol_function",
                        value=function,
                    )
                )

            metadata = comm.get("metadata", {}) or {}
            for field in sorted(SAFE_COMM_METADATA_FIELDS):
                if field in metadata:
                    observations.append(
                        _observation(
                            asset=asset,
                            asset_id=asset_id,
                            protocol=protocol,
                            field=field,
                            value=metadata[field],
                        )
                    )

    return {
        "source": "guppy-ics",
        "capture_id": capture_id,
        "observations": observations,
    }


def submit_observations_to_oads(state: Any, capture_id: str, client: OADSClient) -> Optional[Any]:
    payload = build_observations_payload(state, capture_id)
    try:
        return client.submit_observations(payload)
    except (OSError, urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
        print(f"WARNING: OADS observation submit failed: {exc}")
        return None


def fetch_oads_assets(client: OADSClient) -> List[Dict[str, Any]]:
    try:
        payload = client.get_assets()
    except (OSError, urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
        print(f"WARNING: OADS asset fetch failed: {exc}")
        return []

    return normalize_oads_assets_payload(payload)


def normalize_oads_assets_payload(payload: Any) -> List[Dict[str, Any]]:
    if isinstance(payload, list):
        return [a for a in payload if isinstance(a, dict)]
    if isinstance(payload, dict):
        for key in ("assets", "items", "results", "data"):
            assets = payload.get(key)
            if isinstance(assets, list):
                return [a for a in assets if isinstance(a, dict)]
    return []


def debug_payload_preview(payload: Any, *, max_chars: int = 4000) -> str:
    if payload is None:
        return "null"

    try:
        text = json.dumps(_plain(payload), indent=2, sort_keys=True, default=str)
    except TypeError:
        text = str(payload)

    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n... truncated ..."


def attach_oads_profiles(state: Any, oads_assets: Iterable[Dict[str, Any]]) -> int:
    by_mac: Dict[str, Dict[str, Any]] = {}
    by_ip: Dict[str, Dict[str, Any]] = {}

    for profile in oads_assets:
        for mac in _extract_profile_values(profile, "mac"):
            by_mac[_normalize_mac(mac)] = profile
        for ip in _extract_profile_values(profile, "ip"):
            by_ip[str(ip)] = profile

    matched = 0
    for _, asset in _iter_assets(state):
        profile = None
        for mac in _iter_values(asset.get("identifiers", {}).get("mac")):
            profile = by_mac.get(_normalize_mac(mac))
            if profile:
                break

        if not profile:
            for ip in _iter_values(asset.get("identifiers", {}).get("ip")):
                profile = by_ip.get(str(ip))
                if profile:
                    break

        if profile:
            asset["oads_profile"] = profile
            matched += 1

    return matched


def guppy_match_key_counts(state: Any) -> Dict[str, int]:
    macs = set()
    ips = set()
    for _, asset in _iter_assets(state):
        for mac in _iter_values(asset.get("identifiers", {}).get("mac")):
            macs.add(_normalize_mac(mac))
        for ip in _iter_values(asset.get("identifiers", {}).get("ip")):
            ips.add(str(ip))
    return {"mac": len(macs), "ip": len(ips)}


def oads_match_key_counts(oads_assets: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    macs = set()
    ips = set()
    for profile in oads_assets:
        for mac in _extract_profile_values(profile, "mac"):
            macs.add(_normalize_mac(mac))
        for ip in _extract_profile_values(profile, "ip"):
            ips.add(str(ip))
    return {"mac": len(macs), "ip": len(ips)}


def _iter_assets(state: Any):
    assets = getattr(state, "assets", {}) or {}
    for asset_id, asset in assets.items():
        if isinstance(asset, dict):
            yield asset_id, asset


def _iter_comms(state: Any):
    comms = getattr(state, "communications", {}) or {}
    values = comms.values() if isinstance(comms, dict) else comms
    for comm in values:
        if isinstance(comm, dict):
            yield comm


def _iter_values(value: Any):
    if value is None:
        return []
    if isinstance(value, (set, list, tuple)):
        return [v for v in value if v is not None]
    if isinstance(value, dict):
        if "value" in value:
            return _iter_values(value.get("value"))
        if "values" in value:
            return _iter_values(value.get("values"))
        return []
    return [value]


def _observation(
    *,
    asset: Dict[str, Any],
    asset_id: str,
    protocol: str,
    field: str,
    value: Any,
) -> Dict[str, Any]:
    ids = asset.get("identifiers", {}) or {}
    return {
        "timestamp": None,
        "mac": _first(ids.get("mac")),
        "ip": _first(ids.get("ip")),
        "protocol": str(protocol),
        "field": str(field),
        "value": _stringify(value),
        "raw_context": {
            "guppy_asset_id": str(asset.get("asset_id") or asset_id),
            "evidence_layer": ",".join(sorted(asset.get("_evidence_layers", set()) or [])),
            "source": "guppy-ics",
        },
    }


def _first(value: Any) -> Optional[str]:
    values = sorted(str(v) for v in _iter_values(value))
    return values[0] if values else None


def _stringify(value: Any) -> str:
    if isinstance(value, (dict, list, tuple, set)):
        return json.dumps(_plain(value), sort_keys=True)
    return str(value)


def _plain(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_plain(v) for v in value]
    return value


def _normalize_mac(value: Any) -> str:
    return str(value).lower()


def _extract_profile_values(profile: Dict[str, Any], key: str) -> List[Any]:
    names = {
        "mac": {
            "mac",
            "macs",
            "primary_mac",
            "mac_address",
            "mac_addresses",
            "macAddress",
            "macAddresses",
        },
        "ip": {
            "ip",
            "ips",
            "ip_address",
            "ip_addresses",
            "ipAddress",
            "ipAddresses",
            "ipv4",
            "ipv4_address",
            "ipv4Address",
            "primary_ip",
        },
    }[key]

    values: List[Any] = []
    for candidate in names:
        values.extend(_iter_values(profile.get(candidate)))

    identifiers = profile.get("identifiers")
    if isinstance(identifiers, dict):
        for candidate in names:
            values.extend(_iter_values(identifiers.get(candidate)))
    elif isinstance(identifiers, list):
        for item in identifiers:
            if isinstance(item, dict):
                item_type = item.get("type") or item.get("kind") or item.get("field")
                if item_type in names and "value" in item:
                    values.append(item["value"])
                else:
                    for candidate in names:
                        if candidate in item:
                            values.extend(_iter_values(item.get(candidate)))

    for collection_key in ("interfaces", "network_interfaces", "addresses"):
        collection = profile.get(collection_key)
        if isinstance(collection, list):
            for item in collection:
                if isinstance(item, dict):
                    for candidate in names:
                        values.extend(_iter_values(item.get(candidate)))

    return values
