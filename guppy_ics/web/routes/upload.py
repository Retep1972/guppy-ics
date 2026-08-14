from pathlib import Path
import os, uuid, threading, shutil, csv
import urllib.error
from io import StringIO
from collections import defaultdict

from fastapi import APIRouter, Request, UploadFile, File
from fastapi.responses import HTMLResponse, StreamingResponse

from guppy_ics.analysis.run import analyze_pcap
from guppy_ics.web.deps import templates
from guppy_ics.web.progress import ProgressBus
from guppy_ics.web.routes.progress import sse_event_stream
from fastapi.responses import StreamingResponse
from guppy_ics.core.communications import filter_communications_for_presentation
from guppy_ics.core.control import CancelToken
from guppy_ics.protocols.registry import available_protocols
from guppy_ics.integrations.oads import (
    OADSClient,
    attach_oads_profiles,
    build_observations_payload,
    debug_payload_preview,
    filter_payload_for_unknown_oads_assets,
    guppy_match_key_counts,
    normalize_oads_assets_payload,
    oads_match_key_counts,
    submit_observations_in_batches,
)

UPLOAD_DIR = Path(__file__).resolve().parents[1] / "uploaded_pcaps"
UPLOAD_DIR.mkdir(exist_ok=True)
TRANSPORT_PROTOCOLS = {"ip", "tcp", "udp"}
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

router = APIRouter()
_progress_buses = {}
_cancel_tokens = {}
_analysis_results = {}
_analysis_oads = {}
_oads_config = {
    "base_url": None,
}

FUNCTION_NORMALIZATION = {
    # voor PROFINET
    "rtc1_io": "controls",

    # Client/server patterns
    "request": "client → server",
    "response": "server → client",

    # Transport / network
    "L4": "transport (L4)",
    "L3": "network (L3)",
}

# -------------------------------------------------
# Helper: human-readable asset label (PUT IT HERE)
# -------------------------------------------------
def is_broadcast_identifier(identifier: str | None) -> bool:
    if not identifier:
        return False
    return identifier.lower() == BROADCAST_MAC

def primary_label(asset: dict) -> str:
    """
    Human-facing label for an asset.
    Priority:
    1) PROFINET station name
    2) MAC address
    3) IP address
    4) Fallback identifier / asset_id
    """
    metadata = asset.get("metadata", {})
    station = metadata.get("station_name")
    if station:
        return station

    identifiers = asset.get("identifiers", {})
    macs = identifiers.get("mac")
    if macs:
        return sorted(macs)[0]

    ips = identifiers.get("ip")
    if ips:
        return sorted(ips)[0]

    return asset.get("identifier", asset.get("asset_id"))

# helper function
def normalize_function(func: str | None) -> str | None:
    if not func:
        return None
    return FUNCTION_NORMALIZATION.get(func, func)


@router.get("/upload", response_class=HTMLResponse)
def upload_page(request: Request):
    oads_context = _oads_template_context()
    return templates.TemplateResponse(
        "upload.html",
        {
            "request": request,
            "protocols": available_protocols(),
            **oads_context,
        },
    )

@router.post("/upload/run", response_class=HTMLResponse)
async def run_upload(request: Request, pcap: UploadFile = File(...)):
    form = await request.form()
    selected_protocols = form.getlist("protocols")
    oads_enabled = _form_enabled(form.get("oads_enhance")) or _env_enabled("GUPPY_OADS_ENABLED")
    oads_url = _resolve_oads_url(form.get("oads_url"))
    _remember_oads_config(oads_url)
    bus_id = str(uuid.uuid4())

    bus = ProgressBus()
    cancel_token = CancelToken()

    _progress_buses[bus_id] = bus
    _cancel_tokens[bus_id] = cancel_token

    suffix = Path(pcap.filename).suffix.lower()
    tmp_path = UPLOAD_DIR / f"{bus_id}{suffix}"

    with tmp_path.open("wb") as f:
        shutil.copyfileobj(pcap.file, f)

    def background_analysis():
        state = analyze_pcap(
            str(tmp_path),
            enabled_protocols=selected_protocols or None,
            progress_cb=bus.push,
            cancel_token=cancel_token,
        )

        _analysis_oads[bus_id] = run_oads_enrichment(
            state,
            capture_id=Path(pcap.filename).stem or bus_id,
            enabled=oads_enabled,
            base_url=oads_url,
        )

        bus.done()
        _analysis_results[bus_id] = state

        # cleanup
        _cancel_tokens.pop(bus_id, None)
        _progress_buses.pop(bus_id, None)

    threading.Thread(target=background_analysis, daemon=True).start()

    return templates.TemplateResponse(
        "upload_progress.html",
        {
            "request": request,
            "bus_id": bus_id,
        },
    )

@router.get("/upload/progress")
def upload_progress(bus_id: str):
    bus = _progress_buses.get(bus_id)
    if not bus:
        return StreamingResponse(iter([]), media_type="text/event-stream")

    return StreamingResponse(
        sse_event_stream(bus),
        media_type="text/event-stream",
    )

def filter_communications_for_ui(communications):
    """
    Collapse protocol stacks for UI presentation.
    Rules:
    - Prefer application protocols over transport (ip/tcp/udp)
    - Fallback to tcp/udp if no application protocol exists
    - Never show pure IP
    """
    filtered = filter_communications_for_presentation(
        communications,
        transport_protocols=TRANSPORT_PROTOCOLS,
    )
    for selected in filtered:
        meta = selected.get("metadata", {})
        if meta.get("dst_port") and selected.get("dst_ip"):
            selected["dst_display"] = f"{selected['dst_label']} ({selected['dst_ip']})"
        else:
            selected["dst_display"] = selected.get("dst_label")
    return filtered

    flows = defaultdict(list)

    # Group communications into flows
    for c in communications:
        meta = c.get("metadata", {})
        dst_port = meta.get("dst_port")

        key = (
            c.get("src_asset_id"),
            c.get("dst_asset_id"),
            dst_port,
        )

        flows[key].append(c)

    filtered = []

    for comms in flows.values():
        selected = None

        # 1️⃣ Prefer non-transport (application) protocols
        for c in comms:
            if c.get("protocol") not in TRANSPORT_PROTOCOLS:
                selected = c
                break

        # 2️⃣ Fallback to tcp/udp
        if not selected:
            for c in comms:
                if c.get("protocol") in {"tcp", "udp"}:
                    selected = c
                    break

        if not selected:
            continue

        # ----------------------------
        # Presentation enrichment
        # ----------------------------
        meta = selected.get("metadata", {})
        if meta.get("dst_port") and selected.get("dst_ip"):
            selected["dst_display"] = f"{selected['dst_label']} ({selected['dst_ip']})"
        else:
            selected["dst_display"] = selected.get("dst_label")

        filtered.append(selected)

    return filtered


def build_topology_from_communications(communications, state):
    """
    Build adjacency lists (topology) from communications already filtered for UI.
    """
    def asset_display(asset):
        """
        station_name (ip) | ip | mac
        """
        if not asset:
            return "unknown"

        label = asset.get("label") or asset.get("identifier") or asset.get("asset_id")

        ids = asset.get("identifiers", {})
        ips = ids.get("ip")
        macs = ids.get("mac")

        if ips:
            return f"{label} ({sorted(ips)[0]})"
        if macs:
            return f"{label} ({sorted(macs)[0]})"
        return label

    topology = {}

    for c in communications:
        src_asset = state.assets.get(c["src_asset_id"])
        dst_asset = state.assets.get(c["dst_asset_id"])

        src_disp = asset_display(src_asset)
        dst_disp = asset_display(dst_asset)

        proto = c.get("protocol", "unknown")
        func = c.get("function")
        meta = c.get("metadata", {})

        label_parts = [proto]
        if func:
            label_parts.append(func)
        if "dst_port" in meta:
            label_parts.append(f"port {meta['dst_port']}")

        edge_label = " / ".join(label_parts)

        topology.setdefault(src_disp, set()).add(f"{edge_label} → {dst_disp}")

    # Normalize for Jinja
    return {k: sorted(v) for k, v in topology.items()}

@router.get("/upload/result", response_class=HTMLResponse)
def upload_result(request: Request, bus_id: str):
    
    state = _analysis_results.get(bus_id)
    if not state:
        oads_context = _oads_template_context()
        return templates.TemplateResponse(
            "upload.html",
            {
                "request": request,
                "error": "Analysis not finished or not found.",
                "protocols": available_protocols(),
                **oads_context,
            },
        )

    # -------------------------
    # Assets
    # -------------------------
    assets = []
    asset_labels = {}

    for a in state.assets.values():
        a = dict(a)

        # normalize sets for Jinja
        a["protocols"] = sorted(list(a.get("protocols", [])))
        a["identifiers"] = {
            k: sorted(list(v)) for k, v in a.get("identifiers", {}).items()
        }

        label = primary_label(a)
        profile = a.get("oads_profile")
        if isinstance(profile, dict):
            a["oads_summary"] = summarize_oads_profile(profile)

        if is_broadcast_identifier(label):
            a["role"] = "broadcast"
            a["vendor"] = None
        else:
            asset_labels[a["asset_id"]] = label
            a["label"] = label

        assets.append(a)

    # -------------------------
    # Helpers
    # -------------------------
    def first_ip(asset):
        if not asset:
            return None
        ips = asset.get("identifiers", {}).get("ip")
        return sorted(ips)[0] if ips else None

    def asset_display(asset):
        if not asset:
            return "unknown"

        label = asset.get("label") or asset.get("asset_id")

        ids = asset.get("identifiers", {})

        ips = ids.get("ip")
        ipv6s = ids.get("ipv6")
        macs = ids.get("mac")

        # Prefer IPv4
        if ips:
            return f"{label} (IP: {sorted(ips)[0]})"

        # Then IPv6 (explicitly marked!)
        if ipv6s:
            #print(ipv6s)
            return f"{label} (IPV6: {sorted(ipv6s)[0]})"

        # Finally MAC
        if macs:
            return f"{label} (MAC: {sorted(macs)[0]})"

        return label


    # -------------------------
    # Communications + Topology
    # -------------------------
    communications = []
    topology = {}

    for comm in state.communications.values():
        c = dict(comm)
        c["function"] = normalize_function(c.get("function"))

        src_asset = state.assets.get(c["src_asset_id"])
        dst_asset = state.assets.get(c["dst_asset_id"])

        # labels & IPs for UI
        c["src_label"] = asset_labels.get(c["src_asset_id"])
        c["dst_label"] = asset_labels.get(c["dst_asset_id"])
        c["src_ip"] = first_ip(src_asset)
        c["dst_ip"] = first_ip(dst_asset)

        communications.append(c)

        # ---------
        # Topology
        # ---------
        src_disp = asset_display(src_asset)
        dst_disp = asset_display(dst_asset)

        proto = c.get("protocol", "unknown")
        func = c.get("function")
        meta = c.get("metadata", {})

        label_parts = [proto]
        if func:
            label_parts.append(func)
        if "dst_port" in meta:
            label_parts.append(f"port {meta['dst_port']}")

        edge_label = " / ".join(label_parts)

        topology.setdefault(src_disp, set()).add(
            f"{edge_label} → {dst_disp}"
        )

    # normalize topology for Jinja
    topology = {k: sorted(v) for k, v in topology.items()}
    communications = filter_communications_for_ui(communications)
    topology = build_topology_from_communications(communications, state)
    # -------------------------
    # Render
    # -------------------------

    VISIBILITY_LABELS = {
        "observed_l3": ("Observed (IP)", "green"),
        "observed_l2_only": ("Observed (L2 only)", "blue"),
        "inferred": ("Inferred", "gray"),
    }

    for a in assets:
        vis = a.get("visibility", "inferred")
        label, color = VISIBILITY_LABELS.get(vis, ("Unknown", "gray"))
        a["visibility_label"] = label
        a["visibility_color"] = color

    return templates.TemplateResponse(
        "upload_result.html",
        {
            "request": request,
            "summary": state.summary(),
            "assets": assets,
            "communications": communications,
            "topology": topology,   
            "evidence": summarize_evidence(getattr(state, "evidence", []), asset_labels),
            "special_addresses": sorted(getattr(state, "special_addresses", {}).values(), key=lambda x: x.get("identifier", "")),
            "oads_status": _analysis_oads.get(bus_id),
        },
    )

@router.post("/upload/cancel")
def cancel_upload(bus_id: str):
    token = _cancel_tokens.get(bus_id)
    if token:
        token.cancel()
    return {"status": "cancelled"}

@router.get("/upload/firewall.csv")
def export_firewall_csv(bus_id: str):
    """
    Export observed TCP/UDP communications as per-host firewall rules.
    """
    state = _analysis_results.get(bus_id)
    if not state:
        return {"error": "analysis not found"}

    def first_ip(asset):
        if not asset:
            return None
        ips = asset.get("identifiers", {}).get("ip")
        return sorted(ips)[0] if ips else None

    def asset_label(asset):
        """
        Derive a human-meaningful label for firewall export.
        """
        if not asset:
            return None

        # Station / device name
        name = asset.get("metadata", {}).get("station_name")
        if name:
            return name

        # Role
        role = asset.get("role")
        if role:
            return role.upper()

        # IP address
        ips = asset.get("identifiers", {}).get("ip")
        if ips:
            return sorted(ips)[0]

        # MAC address
        macs = asset.get("identifiers", {}).get("mac")
        if macs:
            return sorted(macs)[0]

        return asset.get("asset_id")

    rows_by_host = {}

    for comm in state.communications.values():
        meta = comm.get("metadata", {})
        src_port = meta.get("src_port")
        dst_port = meta.get("dst_port")
        if not src_port or not dst_port:
            continue

        src_asset = state.assets.get(comm["src_asset_id"])
        dst_asset = state.assets.get(comm["dst_asset_id"])

        # Only export rules for assets directly observed at L3
        if (
            not src_asset
            or not dst_asset
            or src_asset.get("visibility") != "observed_l3"
            or dst_asset.get("visibility") != "observed_l3"
        ):
            continue

        # Skip broadcast endpoints
        if (
            is_broadcast_identifier(src_asset.get("identifier") if src_asset else None)
            or is_broadcast_identifier(dst_asset.get("identifier") if dst_asset else None)
        ):
            continue

        src_ip = first_ip(src_asset)
        dst_ip = first_ip(dst_asset)
        if not src_ip or not dst_ip:
            continue

        src_label = asset_label(src_asset) or src_ip
        dst_label = asset_label(dst_asset) or dst_ip

        transport_proto = meta.get("transport", "tcp")

        # Outbound rule
        rows_by_host.setdefault(src_ip, []).append([
            src_label,
            src_ip,
            dst_label,
            dst_ip,
            transport_proto,
            src_port,
            dst_port,
            "outbound",
        ])

        # Inbound rule
        rows_by_host.setdefault(dst_ip, []).append([
            dst_label,
            dst_ip,
            src_label,
            src_ip,
            transport_proto,
            src_port,
            dst_port,
            "inbound",
        ])


    output = StringIO()
    writer = csv.writer(output)

    header = [
        "host_label",
        "host_ip",
        "peer_label",
        "peer_ip",
        "protocol",
        "src_port",
        "dst_port",
        "direction",
    ]

    for host_ip in sorted(rows_by_host):
        host_rows = rows_by_host[host_ip]
        host_label = host_rows[0][0]

        # Host section header (comment line)
        writer.writerow([f"# Host: {host_label} ({host_ip})"])
        writer.writerow(header)

        for row in host_rows:
            writer.writerow(row)

        writer.writerow([])  # blank line between hosts

    output.seek(0)

    return StreamingResponse(
        output,
        media_type="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=firewall_rules_{bus_id}.csv"
        },
    )

def run_oads_enrichment(
    state,
    *,
    capture_id: str,
    enabled: bool,
    base_url: str,
):
    if not enabled:
        return None

    status = _empty_oads_status(state, base_url=base_url)

    if not base_url:
        status["message"] = "OADS enhancement was enabled, but the base URL is missing."
        return status

    client = OADSClient(base_url=base_url, timeout=_oads_timeout())
    payload = build_observations_payload(state, capture_id)
    status["observations"] = len(payload.get("observations", []))

    try:
        health_response = client.health()
        status["health"] = True
        status["health_response_preview"] = debug_payload_preview(health_response)
    except (OSError, urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
        status["health_error"] = str(exc)

    preflight_profiles = []
    try:
        preflight_assets_response = client.get_assets()
        preflight_profiles = normalize_oads_assets_payload(preflight_assets_response)
        status["preflight_assets"] = True
        status["preflight_assets_count"] = len(preflight_profiles)
        status["oads_keys"] = oads_match_key_counts(preflight_profiles)
    except (OSError, urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
        status["preflight_assets_error"] = str(exc)

    submit_payload = payload
    if preflight_profiles and _oads_skip_known_assets():
        submit_payload, skipped = filter_payload_for_unknown_oads_assets(payload, preflight_profiles)
        status["skipped_known_observations"] = skipped
        status["submit_observations"] = len(submit_payload.get("observations", []))
    else:
        status["submit_observations"] = status["observations"]

    try:
        submit_result = submit_observations_in_batches(
            client,
            submit_payload,
            batch_size=_oads_batch_size(),
        )
        status["submit_response_preview"] = debug_payload_preview(submit_result)
        status["submitted"] = True
        status["submitted_observations"] = submit_result["submitted_observations"]
        if submit_result.get("failed"):
            status["submit_error"] = submit_result.get("error")
            status["partial_submit"] = submit_result["submitted_observations"] > 0
    except (OSError, urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
        status["submit_error"] = str(exc)
        if status.get("health") or status.get("preflight_assets"):
            status["message"] = (
                f"OADS is reachable, but POST /api/v1/observations timed out after building "
                f"{status['observations']} observation(s)."
            )
        else:
            status["message"] = f"OADS submit failed after building {status['observations']} observation(s)."
        if preflight_profiles:
            matched = attach_oads_profiles(state, preflight_profiles)
            status["matched"] = matched
            status["fetched_assets"] = len(preflight_profiles)
            status["message"] += f" Attached {matched} existing OADS profile(s) from preflight."
        return status

    try:
        assets_response = client.get_assets()
        status["assets_response_preview"] = debug_payload_preview(assets_response)
        profiles = normalize_oads_assets_payload(assets_response)
        status["fetched"] = True
    except (OSError, urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
        status["fetch_error"] = str(exc)
        status["message"] = "OADS accepted observations, but Guppy could not fetch enriched assets."
        return status

    status["fetched_assets"] = len(profiles)
    status["oads_keys"] = oads_match_key_counts(profiles)
    matched = attach_oads_profiles(state, profiles)
    status["matched"] = matched
    status["ok"] = matched > 0

    if not profiles:
        status["message"] = (
            f"Submitted {status['submitted_observations']} observation(s), but OADS returned 0 assets."
        )
    elif status["oads_keys"]["mac"] == 0 and status["oads_keys"]["ip"] == 0:
        status["message"] = (
            f"OADS returned {status['fetched_assets']} asset(s), but none had MAC/IP identifiers Guppy can match."
        )
    elif matched == 0:
        status["message"] = (
            f"OADS returned {status['fetched_assets']} asset(s), but none matched Guppy assets by MAC or IP."
        )
    else:
        status["message"] = (
            f"Submitted {status['submitted_observations']} observation(s), fetched {status['fetched_assets']} OADS asset(s), "
            f"and matched {matched} Guppy asset(s)."
        )
        if status["skipped_known_observations"]:
            status["message"] += f" Skipped {status['skipped_known_observations']} observation(s) for assets already known to OADS."

    return status


def summarize_evidence(evidence, asset_labels):
    rows = []
    for item in list(evidence or [])[:200]:
        if not isinstance(item, dict):
            continue
        attrs = item.get("attributes", {}) or {}
        source_asset = item.get("source_asset")
        rows.append(
            {
                "type": item.get("type", "evidence"),
                "protocol": item.get("protocol", "unknown"),
                "source": asset_labels.get(source_asset, attrs.get("src_ip") or source_asset or "-"),
                "summary": _evidence_summary(item),
            }
        )
    return rows


def _evidence_summary(item):
    attrs = item.get("attributes", {}) or {}
    parts = []
    for key in (
        "hostname",
        "vendor_class",
        "message_type",
        "queries",
        "answers",
        "types",
        "st",
        "nt",
        "dst_port",
        "scope",
        "server",
        "location",
    ):
        value = attrs.get(key)
        if value in (None, "", [], {}):
            continue
        parts.append(f"{key}: {_short_value(value)}")
    return " | ".join(parts) if parts else _short_value(attrs)


def _short_value(value, max_len=220):
    text = str(value)
    return text if len(text) <= max_len else text[:max_len] + "..."

def _empty_oads_status(state, *, base_url: str) -> dict:
    return {
        "enabled": True,
        "ok": False,
        "base_url": base_url,
        "observations": 0,
        "submit_observations": 0,
        "submitted_observations": 0,
        "skipped_known_observations": 0,
        "partial_submit": False,
        "submitted": False,
        "submit_error": None,
        "fetched": False,
        "fetch_error": None,
        "fetched_assets": 0,
        "health": False,
        "health_error": None,
        "health_response_preview": None,
        "preflight_assets": False,
        "preflight_assets_error": None,
        "preflight_assets_count": 0,
        "matched": 0,
        "guppy_keys": guppy_match_key_counts(state),
        "oads_keys": {"mac": 0, "ip": 0},
        "submit_response_preview": None,
        "assets_response_preview": None,
        "message": "",
    }


def _oads_timeout() -> float:
    try:
        return float(os.environ.get("GUPPY_OADS_TIMEOUT", "5"))
    except ValueError:
        return 5.0


def _oads_batch_size() -> int:
    try:
        return max(1, int(os.environ.get("GUPPY_OADS_BATCH_SIZE", "100")))
    except ValueError:
        return 100


def _oads_skip_known_assets() -> bool:
    return os.environ.get("GUPPY_OADS_SKIP_KNOWN_ASSETS", "true").strip().lower() in {"1", "true", "yes", "on"}

def summarize_oads_profile(profile: dict) -> dict:
    fields = [
        "name",
        "hostname",
        "vendor",
        "manufacturer",
        "model",
        "device_type",
        "os",
        "embedded_os",
        "firmware",
        "firmware_version",
    ]
    return {field: profile.get(field) for field in fields if profile.get(field)}

def _env_enabled(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}

def _form_enabled(value) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}

def _resolve_oads_url(form_value) -> str:
    return str(
        form_value
        or _oads_config.get("base_url")
        or os.environ.get("GUPPY_OADS_URL")
        or "http://localhost:8000"
    ).strip()

def _remember_oads_config(base_url: str) -> None:
    if base_url:
        _oads_config["base_url"] = base_url

def _oads_template_context() -> dict:
    return {
        "oads_enabled": _env_enabled("GUPPY_OADS_ENABLED") or bool(_oads_config.get("base_url")),
        "oads_url": _oads_config.get("base_url") or os.environ.get("GUPPY_OADS_URL", "http://localhost:8000"),
    }
