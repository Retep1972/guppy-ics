from pathlib import Path
import html, os, uuid, threading, shutil, csv, tempfile, zipfile
import urllib.error
import re
from datetime import datetime
from io import StringIO
from collections import defaultdict
from typing import Optional

from fastapi import APIRouter, Request, UploadFile, File, Form
from fastapi.responses import FileResponse, HTMLResponse, Response, StreamingResponse

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
from guppy_ics.segmentation import assess_segmentation, write_segmentation_outputs
from guppy_ics.segmentation.report import render_html_report

UPLOAD_DIR = Path(__file__).resolve().parents[1] / "uploaded_pcaps"
UPLOAD_DIR.mkdir(exist_ok=True)
ALLOWED_PCAP_SUFFIXES = {".pcap", ".pcapng"}
MAX_RECENT_UPLOADS = 10
TRANSPORT_PROTOCOLS = {"ip", "tcp", "udp"}
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

router = APIRouter()
_progress_buses = {}
_cancel_tokens = {}
_analysis_results = {}
_analysis_oads = {}
_analysis_errors = {}
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


def asset_topology_display(asset: dict | None) -> str:
    """
    Human-facing topology label.
    Prefer a device name when known; otherwise show device type/model/role,
    then include the best stable identifier in parentheses.
    """
    if not asset:
        return "unknown"

    identifiers = asset.get("identifiers", {}) or {}
    profile = asset.get("oads_profile") or {}
    metadata = asset.get("metadata", {}) or {}

    name = _first_present(
        metadata.get("station_name"),
        metadata.get("hostname"),
        profile.get("name") if isinstance(profile, dict) else None,
        profile.get("hostname") if isinstance(profile, dict) else None,
        _first_identifier(identifiers, "hostname"),
    )
    device_type = _first_present(
        profile.get("device_type") if isinstance(profile, dict) else None,
        profile.get("model") if isinstance(profile, dict) else None,
        asset.get("role"),
    )
    fallback = asset.get("label") or asset.get("identifier") or asset.get("asset_id")
    label = name or _humanize_device_type(device_type) or fallback

    identifier = (
        _first_identifier(identifiers, "ip")
        or _first_identifier(identifiers, "ipv6")
        or _first_identifier(identifiers, "mac")
    )
    if identifier and str(identifier) != str(label):
        return f"{label} ({identifier})"
    return str(label)


def _first_identifier(identifiers: dict, key: str):
    values = identifiers.get(key)
    if not values:
        return None
    return sorted(values)[0]


def _first_present(*values):
    for value in values:
        if not _is_empty_value(value):
            return value
    return None


def _humanize_device_type(value):
    if not value:
        return None
    return str(value).replace("_", " ")

# helper function
def normalize_function(func: str | None) -> str | None:
    if not func:
        return None
    return FUNCTION_NORMALIZATION.get(func, func)


def recent_uploaded_pcaps(limit: int = MAX_RECENT_UPLOADS):
    files = sorted(
        _uploaded_pcap_files(),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )[:limit]
    return [
        {
            "name": path.name,
            "label": _display_upload_name(path),
            "size": _format_size(path.stat().st_size),
            "modified": datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d %H:%M"),
        }
        for path in files
    ]


def prune_uploaded_pcaps(limit: int = MAX_RECENT_UPLOADS) -> None:
    files = sorted(
        _uploaded_pcap_files(),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    for path in files[limit:]:
        try:
            path.unlink()
        except OSError:
            pass


def _uploaded_pcap_files():
    return [
        path
        for path in UPLOAD_DIR.iterdir()
        if path.is_file() and path.suffix.lower() in ALLOWED_PCAP_SUFFIXES
    ]


def _safe_upload_name(filename: str | None) -> str:
    raw_name = Path(filename or "capture.pcap").name
    suffix = Path(raw_name).suffix.lower()
    stem = Path(raw_name).stem or "capture"
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", stem).strip("._-") or "capture"
    if suffix not in ALLOWED_PCAP_SUFFIXES:
        suffix = ".pcap"
    return f"{stem[:80]}{suffix}"


def _display_upload_name(path: Path) -> str:
    name = path.name
    if "_" in name:
        prefix, rest = name.split("_", 1)
        try:
            uuid.UUID(prefix)
            return rest
        except ValueError:
            pass
    return name


def _format_size(size: int) -> str:
    if size >= 1024 * 1024:
        return f"{size / (1024 * 1024):.1f} MB"
    if size >= 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size} B"


def _resolve_recent_pcap(name: str) -> Path | None:
    if Path(name).name != name:
        return None
    candidate = (UPLOAD_DIR / Path(name).name).resolve()
    upload_root = UPLOAD_DIR.resolve()
    if candidate.parent != upload_root:
        return None
    if candidate.suffix.lower() not in ALLOWED_PCAP_SUFFIXES:
        return None
    if not candidate.exists() or not candidate.is_file():
        return None
    return candidate


def _capture_id_from_stored_name(path: Path) -> str:
    display_name = _display_upload_name(path)
    return Path(display_name).stem or path.stem


def _upload_template_response(request: Request, *, error: str):
    prune_uploaded_pcaps()
    oads_context = _oads_template_context()
    return templates.TemplateResponse(
        request,
        "upload.html",
        {
            "request": request,
            "protocols": available_protocols(),
            "recent_pcaps": recent_uploaded_pcaps(),
            "error": error,
            **oads_context,
        },
    )


def _start_background_analysis(
    *,
    bus_id: str,
    pcap_path: Path,
    capture_id: str,
    selected_protocols,
    oads_enabled: bool,
    oads_url: str,
) -> None:
    bus = ProgressBus()
    cancel_token = CancelToken()
    _progress_buses[bus_id] = bus
    _cancel_tokens[bus_id] = cancel_token

    def background_analysis():
        try:
            state = analyze_pcap(
                str(pcap_path),
                enabled_protocols=selected_protocols or None,
                progress_cb=bus.push,
                cancel_token=cancel_token,
            )

            _analysis_oads[bus_id] = run_oads_enrichment(
                state,
                capture_id=capture_id,
                enabled=oads_enabled,
                base_url=oads_url,
            )

            _analysis_results[bus_id] = state
        except Exception as exc:
            _analysis_errors[bus_id] = f"PCAP analysis failed: {exc}"
        finally:
            bus.done()
            _cancel_tokens.pop(bus_id, None)
            _progress_buses.pop(bus_id, None)

    threading.Thread(target=background_analysis, daemon=True).start()


@router.get("/upload", response_class=HTMLResponse)
def upload_page(request: Request):
    prune_uploaded_pcaps()
    oads_context = _oads_template_context()
    return templates.TemplateResponse(
        request,
        "upload.html",
        {
            "request": request,
            "protocols": available_protocols(),
            "recent_pcaps": recent_uploaded_pcaps(),
            **oads_context,
        },
    )

@router.post("/upload/run", response_class=HTMLResponse)
async def run_upload(request: Request, pcap: Optional[UploadFile] = File(None)):
    form = await request.form()
    selected_protocols = form.getlist("protocols")
    oads_enabled = _form_enabled(form.get("oads_enhance")) or _env_enabled("GUPPY_OADS_ENABLED")
    oads_url = _resolve_oads_url(form.get("oads_url"))
    _remember_oads_config(oads_url)
    bus_id = str(uuid.uuid4())

    if not pcap or not pcap.filename:
        return _upload_template_response(
            request,
            error="Choose a PCAP file or reuse one of the recent uploads.",
        )

    suffix = Path(pcap.filename).suffix.lower()
    if suffix not in ALLOWED_PCAP_SUFFIXES:
        return _upload_template_response(
            request,
            error="Only .pcap and .pcapng files are supported.",
        )

    tmp_path = UPLOAD_DIR / f"{bus_id}_{_safe_upload_name(pcap.filename)}"

    try:
        with tmp_path.open("wb") as f:
            shutil.copyfileobj(pcap.file, f)
        prune_uploaded_pcaps()
        _start_background_analysis(
            bus_id=bus_id,
            pcap_path=tmp_path,
            capture_id=Path(pcap.filename).stem or bus_id,
            selected_protocols=selected_protocols,
            oads_enabled=oads_enabled,
            oads_url=oads_url,
        )
    except Exception as exc:
        return _upload_template_response(
            request,
            error=f"Could not start PCAP analysis: {exc}",
        )

    return templates.TemplateResponse(
        request,
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
    topology = {}

    for c in communications:
        src_asset = state.assets.get(c["src_asset_id"])
        dst_asset = state.assets.get(c["dst_asset_id"])

        src_disp = asset_topology_display(src_asset)
        dst_disp = asset_topology_display(dst_asset)

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

    for item in getattr(state, "evidence", []) or []:
        attrs = item.get("attributes", {}) or {}
        src_asset = state.assets.get(item.get("source_asset"))
        src_disp = asset_topology_display(src_asset)
        if src_disp == "unknown":
            continue

        if item.get("type") == "sdp_media" and attrs.get("destination_ip"):
            destination = _media_endpoint(attrs.get("destination_ip"), attrs.get("destination_port"))
            media = attrs.get("media_type") or "media"
            transport = attrs.get("transport") or "sdp"
            topology.setdefault(src_disp, set()).add(
                f"sdp / advertises {media} / {transport} -> {destination}"
            )
        elif item.get("type") == "rtp_stream" and attrs.get("scope") == "multicast":
            destination = _media_endpoint(attrs.get("dst_ip"), attrs.get("dst_port"))
            topology.setdefault(src_disp, set()).add(f"rtp / sends_rtp -> {destination}")
        elif item.get("type") == "igmp_membership" and attrs.get("group"):
            event = attrs.get("event")
            if event in {"membership_report", "membership_report_v3"}:
                topology.setdefault(src_disp, set()).add(f"igmp / joins_multicast -> {attrs['group']}")
            elif event == "leave_group":
                topology.setdefault(src_disp, set()).add(f"igmp / leaves_multicast -> {attrs['group']}")

    # Normalize for Jinja
    return {k: sorted(v) for k, v in topology.items()}


def _media_endpoint(ip_value, port_value=None) -> str:
    if port_value not in (None, ""):
        return f"{ip_value}:{port_value}"
    return str(ip_value)

@router.get("/upload/result", response_class=HTMLResponse)
def upload_result(request: Request, bus_id: str):
    state = _analysis_results.get(bus_id)
    if not state:
        error = _analysis_errors.pop(bus_id, None) or "Analysis not finished or not found."
        oads_context = _oads_template_context()
        return templates.TemplateResponse(
            request,
            "upload.html",
            {
                "request": request,
                "error": error,
                "protocols": available_protocols(),
                "recent_pcaps": recent_uploaded_pcaps(),
                **oads_context,
            },
        )

    return templates.TemplateResponse(
        request,
        "upload_result.html",
        _result_template_context(request, state, bus_id),
    )


def _result_template_context(request: Request, state, bus_id: str) -> dict:
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
            a["oads_profile_json"] = debug_payload_preview(profile, max_chars=0)
        a["identity_summary"] = summarize_asset_identity(a)
        raw_identity = a.get("metadata", {}).get("raw_protocol_identity")
        if isinstance(raw_identity, dict) and raw_identity:
            a["identity_json"] = debug_payload_preview(raw_identity, max_chars=0)

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
        src_disp = asset_topology_display(src_asset)
        dst_disp = asset_topology_display(dst_asset)

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

    return {
        "request": request,
        "summary": state.summary(),
        "assets": assets,
        "communications": communications,
        "topology": topology,
        "evidence": summarize_evidence(getattr(state, "evidence", []), asset_labels),
        "special_addresses": sorted(getattr(state, "special_addresses", {}).values(), key=lambda x: x.get("identifier", "")),
        "oads_status": _analysis_oads.get(bus_id),
    }


@router.get("/upload/report.html")
def export_result_report(request: Request, bus_id: str):
    state = _analysis_results.get(bus_id)
    if not state:
        return HTMLResponse("<h1>Report unavailable</h1><p>Analysis not found.</p>", status_code=404)

    context = _result_template_context(request, state, bus_id)
    report = render_result_report_html(context)
    return Response(
        report,
        media_type="text/html; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="guppy_result_{_safe_report_id(bus_id)}.html"'
        },
    )


def render_result_report_html(context: dict) -> str:
    summary_rows = "".join(
        f"<tr><th>{html.escape(str(key))}</th><td>{html.escape(str(value))}</td></tr>"
        for key, value in (context.get("summary") or {}).items()
    )

    asset_rows = []
    for asset in context.get("assets", []) or []:
        asset_rows.append(
            "<tr>"
            f"<td>{html.escape(str(asset.get('label') or asset.get('asset_id') or ''))}</td>"
            f"<td>{html.escape(str(asset.get('role') or ''))}</td>"
            f"<td>{html.escape(str(asset.get('visibility_label') or ''))}</td>"
            f"<td>{html.escape(', '.join(str(p) for p in asset.get('protocols', []) or []))}</td>"
            f"<td>{html.escape(_identifiers_text(asset.get('identifiers', {}) or {}))}</td>"
            f"<td>{html.escape(_summary_dict_text(asset.get('oads_summary') or {}))}</td>"
            f"<td>{html.escape(_identity_summary_text(asset.get('identity_summary') or []))}</td>"
            "</tr>"
        )

    comm_rows = []
    for comm in context.get("communications", []) or []:
        meta = comm.get("metadata", {}) or {}
        comm_rows.append(
            "<tr>"
            f"<td>{html.escape(str(comm.get('protocol') or ''))}</td>"
            f"<td>{html.escape(str(comm.get('function') or ''))}</td>"
            f"<td>{html.escape(str(comm.get('src_label') or comm.get('src_asset_id') or ''))}</td>"
            f"<td>{html.escape(str(comm.get('src_ip') or ''))}</td>"
            f"<td>{html.escape(str(meta.get('src_port') or ''))}</td>"
            f"<td>{html.escape(str(comm.get('dst_display') or comm.get('dst_label') or comm.get('dst_asset_id') or ''))}</td>"
            f"<td>{html.escape(str(comm.get('dst_ip') or ''))}</td>"
            f"<td>{html.escape(str(meta.get('dst_port') or ''))}</td>"
            "</tr>"
        )

    topology_blocks = []
    for source, edges in (context.get("topology") or {}).items():
        edge_items = "".join(f"<li>{html.escape(str(edge))}</li>" for edge in edges)
        topology_blocks.append(f"<li><strong>{html.escape(str(source))}</strong><ul>{edge_items}</ul></li>")

    evidence_rows = []
    for item in context.get("evidence", []) or []:
        evidence_rows.append(
            "<tr>"
            f"<td>{html.escape(str(item.get('protocol') or ''))}</td>"
            f"<td>{html.escape(str(item.get('type') or ''))}</td>"
            f"<td>{html.escape(str(item.get('source') or ''))}</td>"
            f"<td>{html.escape(str(item.get('summary') or ''))}</td>"
            "</tr>"
        )

    special_rows = []
    for item in context.get("special_addresses", []) or []:
        special_rows.append(
            "<tr>"
            f"<td>{html.escape(str(item.get('identifier') or ''))}</td>"
            f"<td>{html.escape(str(item.get('classification') or '').replace('_', ' '))}</td>"
            f"<td>{html.escape(str(item.get('count') or 0))}</td>"
            "</tr>"
        )

    oads_status = context.get("oads_status") or {}
    oads_html = ""
    if oads_status:
        oads_html = f"""
  <section>
    <h2>OADS</h2>
    <table>
      <tbody>
        <tr><th>Status</th><td>{html.escape(str(oads_status.get('message') or ''))}</td></tr>
        <tr><th>Endpoint</th><td>{html.escape(str(oads_status.get('base_url') or ''))}</td></tr>
        <tr><th>Observations built</th><td>{html.escape(str(oads_status.get('observations') or 0))}</td></tr>
        <tr><th>Matched profiles</th><td>{html.escape(str(oads_status.get('matched') or 0))}</td></tr>
      </tbody>
    </table>
  </section>
"""

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Guppy ICS Result Report</title>
  <style>
    body {{ background:#07110b; color:#28ff72; font-family: Consolas, monospace; margin:24px; line-height:1.35; }}
    h1, h2 {{ color:#55ff8a; }}
    table {{ width:100%; border-collapse:collapse; margin:12px 0 24px; }}
    th, td {{ border:1px solid #146b33; padding:7px; vertical-align:top; }}
    th {{ background:#0d2716; text-align:left; }}
    .note {{ color:#b9ffc9; max-width:980px; }}
    ul {{ margin-top:6px; }}
  </style>
</head>
<body>
  <h1>Guppy ICS Result Report</h1>
  <p class="note">Passive analysis report generated from the Guppy result page data. The report reflects observed capture evidence and local/OADS enrichment available at export time.</p>
  <section>
    <h2>Summary</h2>
    <table><tbody>{summary_rows}</tbody></table>
  </section>
  {oads_html}
  <section>
    <h2>Assets</h2>
    <table><thead><tr><th>Asset</th><th>Role</th><th>Visibility</th><th>Protocols</th><th>Identifiers</th><th>OADS Profile</th><th>Identity Evidence</th></tr></thead><tbody>{''.join(asset_rows)}</tbody></table>
  </section>
  <section>
    <h2>Communications</h2>
    <table><thead><tr><th>Protocol</th><th>Function</th><th>Source</th><th>Source IP</th><th>Source Port</th><th>Destination</th><th>Destination IP</th><th>Destination Port</th></tr></thead><tbody>{''.join(comm_rows)}</tbody></table>
  </section>
  <section>
    <h2>Topology</h2>
    <ul>{''.join(topology_blocks) if topology_blocks else '<li>No topology could be derived.</li>'}</ul>
  </section>
  <section>
    <h2>Evidence</h2>
    <table><thead><tr><th>Protocol</th><th>Type</th><th>Source</th><th>Summary</th></tr></thead><tbody>{''.join(evidence_rows)}</tbody></table>
  </section>
  <section>
    <h2>Infrastructure Addresses</h2>
    <table><thead><tr><th>Address</th><th>Classification</th><th>Count</th></tr></thead><tbody>{''.join(special_rows)}</tbody></table>
  </section>
</body>
</html>
"""


def _identifiers_text(identifiers: dict) -> str:
    parts = []
    for key, values in identifiers.items():
        if values:
            parts.append(f"{str(key).upper()}: {', '.join(str(value) for value in values)}")
    return " | ".join(parts)


def _summary_dict_text(values: dict) -> str:
    return " | ".join(
        f"{str(key).replace('_', ' ')}: {value}"
        for key, value in values.items()
        if value not in (None, "", [], {})
    )


def _identity_summary_text(values: list) -> str:
    parts = []
    for item in values:
        if isinstance(item, dict):
            parts.append(f"{item.get('label')}: {item.get('value')}")
        else:
            label = getattr(item, "label", None)
            value = getattr(item, "value", None)
            if label is not None:
                parts.append(f"{label}: {value}")
    return " | ".join(parts)


def _safe_report_id(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", str(value))[:80] or "report"


@router.post("/upload/reuse", response_class=HTMLResponse)
async def reuse_upload(request: Request, stored_pcap: str = Form(...)):
    form = await request.form()
    selected_protocols = form.getlist("protocols")
    oads_enabled = _form_enabled(form.get("oads_enhance")) or _env_enabled("GUPPY_OADS_ENABLED")
    oads_url = _resolve_oads_url(form.get("oads_url"))
    _remember_oads_config(oads_url)

    pcap_path = _resolve_recent_pcap(stored_pcap)
    if not pcap_path:
        return _upload_template_response(
            request,
            error="The selected stored PCAP is no longer available.",
        )

    bus_id = str(uuid.uuid4())
    _start_background_analysis(
        bus_id=bus_id,
        pcap_path=pcap_path,
        capture_id=_capture_id_from_stored_name(pcap_path),
        selected_protocols=selected_protocols,
        oads_enabled=oads_enabled,
        oads_url=oads_url,
    )

    return templates.TemplateResponse(
        request,
        "upload_progress.html",
        {
            "request": request,
            "bus_id": bus_id,
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


@router.get("/upload/segmentation.zip")
def export_segmentation_report(bus_id: str):
    """
    Generate an offline segmentation assessment bundle from the completed upload.
    """
    state = _analysis_results.get(bus_id)
    if not state:
        return {"error": "analysis not found"}

    temp_root = Path(tempfile.mkdtemp(prefix=f"guppy_segmentation_{bus_id}_"))
    out_dir = temp_root / "segmentation"
    assessment = assess_segmentation(state)
    write_segmentation_outputs(assessment, out_dir)

    zip_path = temp_root / f"segmentation_{bus_id}.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(out_dir.iterdir()):
            archive.write(path, arcname=f"segmentation/{path.name}")

    return FileResponse(
        zip_path,
        media_type="application/zip",
        filename=f"segmentation_{bus_id}.zip",
    )


@router.get("/upload/segmentation", response_class=HTMLResponse)
def view_segmentation_report(bus_id: str):
    """
    Render the segmentation report in the browser before downloading the bundle.
    """
    state = _analysis_results.get(bus_id)
    if not state:
        return HTMLResponse("<h1>Segmentation report unavailable</h1><p>Analysis not found.</p>", status_code=404)

    assessment = assess_segmentation(state)
    report_html = render_html_report(assessment)
    escaped_bus_id = html.escape(str(bus_id), quote=True)
    action_bar = f"""
  <div style="position:sticky;top:0;background:#07110b;border-bottom:1px solid #1dd35b;padding:10px 0;margin-bottom:14px;z-index:10">
    <a style="color:#28ff72;border:1px solid #1dd35b;padding:6px 10px;text-decoration:none;margin-right:8px" href="/upload/segmentation.zip?bus_id={escaped_bus_id}">Download segmentation assessment (ZIP)</a>
    <a style="color:#b9ffc9" href="/upload/result?bus_id={escaped_bus_id}">Back to Guppy result</a>
  </div>
"""
    report_html = report_html.replace("<body>", f"<body>{action_bar}", 1)
    return HTMLResponse(report_html)

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
        status["preflight_assets_response_preview"] = debug_payload_preview(preflight_assets_response, max_chars=0)
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
        status["submit_response_preview"] = debug_payload_preview(submit_result, max_chars=0)
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
        status["assets_response_preview"] = debug_payload_preview(assets_response, max_chars=0)
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
        "method",
        "status_code",
        "user_agent",
        "call_id",
        "media_type",
        "destination_ip",
        "destination_port",
        "payload_types",
        "ssrc",
        "packet_count",
        "group",
        "event",
        "message_type",
        "clock_identity",
        "location",
    ):
        value = attrs.get(key)
        if _is_empty_value(value):
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
        "preflight_assets_response_preview": None,
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
    preferred_fields = [
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
        "hardware_version",
        "software_version",
        "product_name",
        "order_number",
        "serial_number",
    ]
    summary = {}
    for field in preferred_fields:
        if profile.get(field):
            summary[field] = _short_value(profile.get(field), max_len=180)

    for path, value in _flatten_profile_fields(profile):
        field = path[-1]
        if field not in preferred_fields or field in summary:
            continue
        summary[field] = _short_value(value, max_len=180)

    return summary


def summarize_asset_identity(asset: dict) -> list[dict]:
    metadata = asset.get("metadata", {}) or {}
    rows = []
    seen = set()

    def add(label, value):
        if _is_empty_value(value):
            return
        key = (label, str(value))
        if key in seen:
            return
        seen.add(key)
        rows.append({"label": label, "value": _short_value(value, max_len=240)})

    for field in (
        "station_name",
        "hostname",
        "order_number",
        "firmware_version",
        "hardware_version",
        "sysObjectID",
    ):
        add(field.replace("_", " "), metadata.get(field))

    raw_identity = metadata.get("raw_protocol_identity")
    if isinstance(raw_identity, dict):
        for protocol, fields in sorted(raw_identity.items()):
            if not isinstance(fields, dict):
                continue
            for field in (
                "system_name",
                "device_id",
                "station_name",
                "model",
                "platform",
                "order_number",
                "firmware_version",
                "hardware_version",
                "management_address",
                "port_id",
                "system_description",
                "software_version",
            ):
                add(f"{protocol} {field.replace('_', ' ')}", fields.get(field))

    return rows


def _flatten_profile_fields(value, path=()):
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _flatten_profile_fields(child, path + (str(key),))
    elif isinstance(value, list):
        for item in value[:20]:
            yield from _flatten_profile_fields(item, path)
    elif not _is_empty_value(value):
        yield path, value


def _is_empty_value(value) -> bool:
    return value is None or value == "" or value == [] or value == {}

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
