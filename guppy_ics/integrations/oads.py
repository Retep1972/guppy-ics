from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional

from guppy_ics.core.addressing import classify_ip_address


SAFE_ASSET_METADATA_FIELDS = {
    "station_name",
    "hostname",
    "sysObjectID",
    "manufacturer_id",
    "vendor_id",
    "order_number",
    "firmware_version",
    "hardware_version",
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

HIGH_VALUE_EVIDENCE_FIELDS = {
    "dhcp": {
        "hostname",
        "fqdn",
        "vendor_class",
        "client_identifier",
        "requested_ip",
        "server_identifier",
        "message_type",
        "parameter_request_list",
    },
    "dns": {"queries", "answers"},
    "llmnr": {"queries", "answers"},
    "mdns": {"queries", "answers"},
    "netbios": {"message_type", "names", "scope"},
    "ssdp": {"host", "st", "nt", "nts", "usn", "server", "location", "cache_control", "scope"},
    "ws_discovery": {
        "types",
        "scopes",
        "endpoint_address",
        "xaddrs",
        "metadata_version",
        "message_id",
        "relates_to",
        "scope",
    },
    "lldp": {
        "chassis_id",
        "port_id",
        "port_description",
        "system_name",
        "system_description",
        "system_capabilities",
        "management_address",
        "order_number",
        "firmware_version",
        "hardware_version",
    },
    "cdp": {
        "device_id",
        "system_name",
        "system_description",
        "software_version",
        "platform",
        "model",
        "port_id",
        "capabilities",
        "management_address",
        "vtp_management_domain",
        "cdp_version",
        "ttl",
    },
}

SERVICE_EVIDENCE_TYPES = {"tcp_service_observation", "udp_service_observation"}
NON_ASSET_ENDPOINT_FIELDS = {"dst_ip", "destination_ip", "group"}
CONTEXT_ONLY_EVIDENCE_FIELDS = {"matched_sdp"}

LOW_VALUE_KNOWN_ASSET_FIELDS = {
    "mac",
    "ip",
    "identity_link",
    "observed_protocol",
    "evidence_type",
    "src_ip",
    "dst_ip",
    "src_mac",
    "dst_mac",
    "src_port",
    "dst_port",
    "server_port",
    "transport",
    "transport_protocol",
    "scope",
    "packet_count",
    "byte_count",
    "first_seen",
    "last_seen",
    "direction",
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

        raw_identity = metadata.get("raw_protocol_identity")
        if isinstance(raw_identity, dict):
            for protocol, fields in sorted(raw_identity.items()):
                if not isinstance(fields, dict):
                    continue
                for field, value in sorted(fields.items()):
                    observations.append(
                        _observation(
                            asset=asset,
                            asset_id=asset_id,
                            protocol=str(protocol),
                            field=str(field),
                            value=value,
                        )
                    )

    for comm in _iter_comms(state):
        protocol = comm.get("protocol") or "unknown"
        metadata = comm.get("metadata", {}) or {}
        comm_context = {
            "source_port": metadata.get("src_port"),
            "destination_port": metadata.get("dst_port"),
            "transport": metadata.get("transport"),
            "function": comm.get("function"),
        }
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
                        raw_context=comm_context,
                    )
                )

            for field in sorted(SAFE_COMM_METADATA_FIELDS):
                if field in metadata:
                    observations.append(
                        _observation(
                            asset=asset,
                            asset_id=asset_id,
                            protocol=protocol,
                            field=field,
                            value=metadata[field],
                            raw_context=comm_context,
                        )
                    )

            if (
                protocol == "onvif"
                and comm.get("function") in {"rtsp_control", "rtsp_media"}
                and asset_id == metadata.get("server_asset_id")
            ):
                observations.append(
                    _observation(
                        asset=asset,
                        asset_id=asset_id,
                        protocol="rtsp",
                        field="media_type",
                        value=metadata.get("media_type", "video"),
                        raw_context=comm_context,
                    )
                )
                for field in ("server", "session", "request_uri", "user_agent"):
                    if not metadata.get(field):
                        continue
                    observations.append(
                        _observation(
                            asset=asset,
                            asset_id=asset_id,
                            protocol="rtsp",
                            field=field,
                            value=metadata[field],
                            raw_context=comm_context,
                        )
                    )

    service_seen = set()
    for evidence in _iter_evidence(state):
        protocol = evidence.get("protocol") or "unknown"
        evidence_type = evidence.get("type") or "evidence"
        asset_id = evidence.get("source_asset") or evidence.get("destination_asset")
        asset = getattr(state, "assets", {}).get(asset_id, {}) if asset_id else {}
        if not asset:
            continue

        attributes = evidence.get("attributes", {}) or {}
        evidence_context = {
            "evidence_type": evidence_type,
            "source_asset": evidence.get("source_asset"),
            "destination_asset": evidence.get("destination_asset"),
            "source": "guppy-ics",
            "evidence_attributes": _context_safe_attributes(attributes),
        }

        if evidence_type in SERVICE_EVIDENCE_TYPES:
            service_key = (
                asset_id,
                protocol,
                attributes.get("server_port") or attributes.get("dst_port"),
                attributes.get("scope"),
            )
            if service_key in service_seen:
                continue
            service_seen.add(service_key)
            for field in ("evidence_type", "dst_port", "server_port", "scope", "transport_protocol"):
                value = evidence_type if field == "evidence_type" else attributes.get(field)
                if _is_empty_value(value):
                    continue
                observations.append(
                    _observation(
                        asset=asset,
                        asset_id=asset_id,
                        protocol=protocol,
                        field=field,
                        value=value,
                        raw_context=evidence_context,
                        timestamp=evidence.get("timestamp"),
                    )
                )
            continue

        observations.append(
            _observation(
                asset=asset,
                asset_id=asset_id,
                protocol=protocol,
                field="evidence_type",
                value=evidence_type,
                raw_context=evidence_context,
                timestamp=evidence.get("timestamp"),
            )
        )
        allowed_fields = HIGH_VALUE_EVIDENCE_FIELDS.get(str(evidence_type), set())
        for field, value in sorted(attributes.items()):
            if allowed_fields and field not in allowed_fields:
                continue
            if _context_only_evidence_field(field, value):
                continue
            observations.append(
                _observation(
                    asset=asset,
                    asset_id=asset_id,
                    protocol=protocol,
                    field=str(field),
                    value=value,
                    raw_context=evidence_context,
                    timestamp=evidence.get("timestamp"),
                )
            )

    observations = _limit_observations(_dedupe_observations(observations))

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


def filter_payload_for_unknown_oads_assets(
    payload: Dict[str, Any],
    oads_assets: Iterable[Dict[str, Any]],
) -> tuple[Dict[str, Any], int]:
    known_macs = set()
    known_ips = set()
    for profile in oads_assets:
        for mac in _extract_profile_values(profile, "mac"):
            known_macs.add(_normalize_mac(mac))
        for ip in _extract_profile_values(profile, "ip"):
            known_ips.add(str(ip))

    kept = []
    skipped = 0
    for obs in payload.get("observations", []) or []:
        mac = _normalize_mac(obs.get("mac")) if obs.get("mac") else None
        ip = str(obs.get("ip")) if obs.get("ip") else None
        known_asset = (mac and mac in known_macs) or (ip and ip in known_ips)
        if known_asset and _skip_known_asset_observation(obs):
            skipped += 1
            continue
        kept.append(obs)

    filtered = dict(payload)
    filtered["observations"] = kept
    return filtered, skipped


def _skip_known_asset_observation(obs: Dict[str, Any]) -> bool:
    field = str(obs.get("field") or "").lower()
    protocol = str(obs.get("protocol") or "").lower()
    if field in LOW_VALUE_KNOWN_ASSET_FIELDS:
        return True
    if protocol in {"tcp", "udp"} and field not in {
        "server",
        "hostname",
        "service_name",
        "product_name",
        "manufacturer",
        "model",
        "firmware_version",
        "serial_number",
    }:
        return True
    return False


def submit_observations_in_batches(
    client: OADSClient,
    payload: Dict[str, Any],
    *,
    batch_size: int = 100,
) -> Dict[str, Any]:
    observations = list(payload.get("observations", []) or [])
    if not observations:
        return {
            "submitted": True,
            "submitted_observations": 0,
            "failed": False,
            "responses": [],
            "error": None,
        }

    responses = []
    submitted = 0
    for index in range(0, len(observations), max(1, batch_size)):
        batch_payload = dict(payload)
        batch_payload["observations"] = observations[index : index + batch_size]
        try:
            responses.append(client.submit_observations(batch_payload))
            submitted += len(batch_payload["observations"])
        except (OSError, urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
            return {
                "submitted": submitted > 0,
                "submitted_observations": submitted,
                "failed": True,
                "responses": responses,
                "error": str(exc),
            }

    return {
        "submitted": True,
        "submitted_observations": submitted,
        "failed": False,
        "responses": responses,
        "error": None,
    }


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

    if max_chars <= 0 or len(text) <= max_chars:
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


def _context_only_evidence_field(field: str, value: Any) -> bool:
    field = str(field)
    if field in CONTEXT_ONLY_EVIDENCE_FIELDS:
        return True
    if field not in NON_ASSET_ENDPOINT_FIELDS:
        return False
    if isinstance(value, (dict, list, tuple, set)):
        return True
    return bool(classify_ip_address(str(value)))


def _context_safe_attributes(attributes: Dict[str, Any]) -> Dict[str, Any]:
    safe = {}
    for key, value in (attributes or {}).items():
        if _is_empty_value(value):
            continue
        safe[str(key)] = _plain(value)
    return safe


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


def _iter_evidence(state: Any):
    evidence = getattr(state, "evidence", []) or []
    for item in evidence:
        if isinstance(item, dict):
            yield item


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


def _dedupe_observations(observations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    deduped = []
    for obs in observations:
        key = (
            _hashable_value(obs.get("timestamp")),
            _normalize_mac(obs.get("mac")) if obs.get("mac") else None,
            _hashable_value(obs.get("ip")),
            _hashable_value(obs.get("protocol")),
            _hashable_value(obs.get("field")),
            _hashable_value(obs.get("value")),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(obs)
    return deduped


def _hashable_value(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool, type(None))):
        return value
    return json.dumps(_plain(value), sort_keys=True, default=str)


def _limit_observations(observations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    limit = _max_observations()
    if limit <= 0 or len(observations) <= limit:
        return observations
    return observations[:limit]


def _max_observations() -> int:
    try:
        return int(os.environ.get("GUPPY_OADS_MAX_OBSERVATIONS", "1500"))
    except ValueError:
        return 1500


def _observation(
    *,
    asset: Dict[str, Any],
    asset_id: str,
    protocol: str,
    field: str,
    value: Any,
    raw_context: Optional[Dict[str, Any]] = None,
    timestamp: Optional[str] = None,
) -> Dict[str, Any]:
    ids = asset.get("identifiers", {}) or {}
    context = {
        "guppy_asset_id": str(asset.get("asset_id") or asset_id),
        "evidence_layer": ",".join(sorted(asset.get("_evidence_layers", set()) or [])),
        "source": "guppy-ics",
    }
    if raw_context:
        context.update({k: v for k, v in raw_context.items() if v is not None})
    return {
        "timestamp": timestamp,
        "mac": _first(ids.get("mac")),
        "ip": _first(ids.get("ip")),
        "protocol": str(protocol),
        "field": str(field),
        "value": _stringify(value),
        "raw_context": context,
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


def _is_empty_value(value: Any) -> bool:
    return value is None or value == "" or value == [] or value == {}


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
