from __future__ import annotations

import ipaddress
from typing import Any, Dict, Iterable, List, Tuple

from guppy_ics.segmentation.models import (
    AssessmentEvidence,
    AssetClassification,
    confidence_level,
)


CATEGORY_LABELS = {
    "process_control": "Process Control",
    "safety": "Safety",
    "operations": "Operations",
    "engineering": "Engineering",
    "ot_services": "OT Services",
    "network_infrastructure": "Network Management",
    "security_infrastructure": "Security Infrastructure",
    "video_surveillance": "Video Surveillance",
    "operational_audio": "Operational Audio",
    "building_automation": "Building Automation",
    "physical_access_control": "Physical Access Control",
    "iot": "IoT",
    "enterprise_it": "Enterprise IT",
    "external": "External / Internet",
    "unknown": "Unknown Assets",
}


SEGMENT_DESCRIPTIONS = {
    "process_control": "Industrial controllers and closely coupled field control assets.",
    "safety": "Safety-related controllers and safety-system communication.",
    "operations": "Operator and supervisory systems such as HMI and SCADA.",
    "engineering": "Engineering and programming workstations.",
    "ot_services": "Shared OT services such as historian, OPC gateway, jump host, and patch services.",
    "network_infrastructure": "Switches, routers, wireless controllers, and management endpoints.",
    "security_infrastructure": "Security monitoring, IDS, and management collectors.",
    "video_surveillance": "Cameras, NVRs, video encoders, and related video systems.",
    "operational_audio": "SIP, RTP, PTP, and operational audio or PA endpoints.",
    "building_automation": "BMS and building automation systems.",
    "physical_access_control": "Badge and physical access control systems.",
    "iot": "Other IoT devices.",
    "enterprise_it": "General-purpose enterprise workstations and servers.",
    "external": "Public Internet or otherwise external endpoints observed in the capture.",
    "unknown": "Assets without enough evidence for confident functional classification.",
}


def classify_assets(state: Any) -> Dict[str, AssetClassification]:
    result: Dict[str, AssetClassification] = {}
    for asset_id, asset in (getattr(state, "assets", {}) or {}).items():
        result[str(asset_id)] = classify_asset(str(asset_id), asset)
    return result


def classify_asset(asset_id: str, asset: Dict[str, Any]) -> AssetClassification:
    texts = _asset_texts(asset)
    protocols = {str(p).lower() for p in asset.get("protocols", set()) if p}
    evidence: List[AssessmentEvidence] = []

    def matched(source: str, detail: str) -> None:
        evidence.append(AssessmentEvidence(source=source, detail=detail))

    if _has_public_ip(asset):
        matched("identifier", "public IP address observed")
        return _classification(asset_id, asset, "external", 0.88, evidence)

    if _contains(texts, ("safety", "sis", "failsafe", "fail-safe")):
        matched("identity", "safety-related asset wording")
        return _classification(asset_id, asset, "safety", 0.82, evidence)

    if protocols & {"onvif", "rtsp"} or _contains(texts, ("camera", "nvr", "video encoder", "cctv", "onvif")):
        matched("protocol" if protocols & {"onvif", "rtsp"} else "identity", "video surveillance evidence")
        return _classification(asset_id, asset, "video_surveillance", 0.86, evidence)

    if protocols & {"sip", "sdp", "rtp", "rtcp"} or _contains(texts, ("sip", "rtp", "speaker", "amplifier", "pa controller", "audio dsp")):
        matched("protocol" if protocols & {"sip", "sdp", "rtp", "rtcp"} else "identity", "operational audio evidence")
        return _classification(asset_id, asset, "operational_audio", 0.84, evidence)

    if protocols & {"lldp", "cdp"} or _contains(texts, ("switch", "router", "firewall", "scalance", "network device")):
        matched("protocol" if protocols & {"lldp", "cdp"} else "identity", "network infrastructure evidence")
        return _classification(asset_id, asset, "network_infrastructure", 0.82, evidence)

    if _contains(texts, ("ids", "security collector", "siem", "sensor")):
        matched("identity", "security infrastructure wording")
        return _classification(asset_id, asset, "security_infrastructure", 0.76, evidence)

    if _contains(texts, ("bacnet", "bms", "building automation")):
        matched("identity", "building automation wording")
        return _classification(asset_id, asset, "building_automation", 0.76, evidence)

    if _contains(texts, ("badge", "access controller", "physical access")):
        matched("identity", "physical access control wording")
        return _classification(asset_id, asset, "physical_access_control", 0.76, evidence)

    if _contains(texts, ("engineering", "programming", "tia portal", "studio 5000")):
        matched("identity", "engineering workstation wording")
        return _classification(asset_id, asset, "engineering", 0.80, evidence)

    if _contains(texts, ("hmi", "scada", "operator")):
        matched("identity", "operations workstation wording")
        return _classification(asset_id, asset, "operations", 0.80, evidence)

    if _contains(texts, ("historian", "opc gateway", "jump host", "patch server", "ot server")):
        matched("identity", "OT service wording")
        return _classification(asset_id, asset, "ot_services", 0.78, evidence)

    if protocols & {"s7comm", "modbus", "profinet", "dnp3", "iec104"} or _contains(
        texts,
        ("plc", "rtu", "remote i/o", "remote io", "vfd", "controller", "simatic", "cpu15"),
    ):
        matched("protocol" if protocols & {"s7comm", "modbus", "profinet", "dnp3", "iec104"} else "identity", "process-control evidence")
        return _classification(asset_id, asset, "process_control", 0.82, evidence)

    if _contains(texts, ("workstation", "server", "laptop", "windows", "linux")):
        matched("identity", "general-purpose IT wording")
        return _classification(asset_id, asset, "enterprise_it", 0.62, evidence)

    if protocols & {"dhcp", "dns", "http", "https", "smb", "rdp", "ssh"}:
        matched("protocol", "general IT/service protocol only")
        return _classification(asset_id, asset, "enterprise_it", 0.48, evidence)

    matched("classification", "insufficient functional evidence")
    return _classification(asset_id, asset, "unknown", 0.30, evidence)


def _classification(
    asset_id: str,
    asset: Dict[str, Any],
    category: str,
    confidence: float,
    evidence: List[AssessmentEvidence],
) -> AssetClassification:
    return AssetClassification(
        asset_id=asset_id,
        name=_asset_name(asset),
        identifiers=_plain_identifiers(asset),
        role=asset.get("role"),
        vendor=asset.get("vendor"),
        protocols=sorted(str(p) for p in asset.get("protocols", set()) if p),
        category=category,
        confidence=confidence,
        confidence_level=confidence_level(confidence),
        evidence=evidence,
    )


def _asset_texts(asset: Dict[str, Any]) -> Tuple[str, ...]:
    values: List[str] = []
    values.extend(_flatten(asset.get("role")))
    values.extend(_flatten(asset.get("vendor")))
    values.extend(_flatten(asset.get("metadata")))
    values.extend(_flatten(asset.get("oads_profile")))
    values.extend(_flatten(asset.get("protocols")))
    return tuple(str(v).lower() for v in values if v not in (None, ""))


def _asset_name(asset: Dict[str, Any]) -> str:
    metadata = asset.get("metadata", {}) or {}
    profile = asset.get("oads_profile", {}) or {}
    identifiers = asset.get("identifiers", {}) or {}
    for value in (
        metadata.get("station_name"),
        metadata.get("hostname"),
        profile.get("name") if isinstance(profile, dict) else None,
        profile.get("hostname") if isinstance(profile, dict) else None,
        _first_identifier(identifiers, "hostname"),
        asset.get("identifier"),
        asset.get("asset_id"),
    ):
        if value not in (None, "", [], {}):
            return str(value)
    return "unknown"


def _plain_identifiers(asset: Dict[str, Any]) -> Dict[str, List[str]]:
    plain: Dict[str, List[str]] = {}
    for key, values in (asset.get("identifiers", {}) or {}).items():
        if isinstance(values, (list, tuple, set)):
            plain[str(key)] = sorted(str(value) for value in values if value not in (None, ""))
        elif values not in (None, ""):
            plain[str(key)] = [str(values)]
    return plain


def _first_identifier(identifiers: Dict[str, Any], key: str) -> str | None:
    values = identifiers.get(key)
    if not values:
        return None
    if isinstance(values, (list, tuple, set)):
        return sorted(str(value) for value in values)[0]
    return str(values)


def _flatten(value: Any) -> Iterable[Any]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _flatten(item)
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            yield from _flatten(item)
    else:
        yield value


def _contains(texts: Iterable[str], needles: Iterable[str]) -> bool:
    joined = " ".join(texts)
    return any(needle in joined for needle in needles)


def _has_public_ip(asset: Dict[str, Any]) -> bool:
    ids = asset.get("identifiers", {}) or {}
    for ip in ids.get("ip", set()) or []:
        try:
            parsed = ipaddress.ip_address(str(ip))
        except ValueError:
            continue
        if not parsed.is_private and not parsed.is_loopback and not parsed.is_link_local and not parsed.is_multicast:
            return True
    return False

