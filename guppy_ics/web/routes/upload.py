from pathlib import Path
import uuid, threading, shutil, csv
from io import StringIO
from collections import defaultdict

from fastapi import APIRouter, Request, UploadFile, File
from fastapi.responses import HTMLResponse, StreamingResponse

from guppy_ics.analysis.run import analyze_pcap
from guppy_ics.web.deps import templates
from guppy_ics.web.progress import ProgressBus
from guppy_ics.web.routes.progress import sse_event_stream
from fastapi.responses import StreamingResponse
from guppy_ics.core.control import CancelToken
from guppy_ics.protocols.registry import available_protocols

UPLOAD_DIR = Path(__file__).resolve().parents[1] / "uploaded_pcaps"
UPLOAD_DIR.mkdir(exist_ok=True)
TRANSPORT_PROTOCOLS = {"ip", "tcp", "udp"}
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

router = APIRouter()
_progress_buses = {}
_cancel_tokens = {}
_analysis_results = {}

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
    return templates.TemplateResponse(
        "upload.html",
        {
            "request": request,
            "protocols": available_protocols(),
        },
    )

@router.post("/upload/run", response_class=HTMLResponse)
async def run_upload(request: Request, pcap: UploadFile = File(...)):
    form = await request.form()
    selected_protocols = form.getlist("protocols")
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

        # 3️⃣ Never show pure IP
        if selected:
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
        return templates.TemplateResponse(
            "upload.html",
            {
                "request": request,
                "error": "Analysis not finished or not found.",
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
            print(ipv6s)
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
    return templates.TemplateResponse(
        "upload_result.html",
        {
            "request": request,
            "summary": state.summary(),
            "assets": assets,
            "communications": communications,
            "topology": topology,   
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
        proto = comm.get("protocol")
        if proto not in ("tcp", "udp"):
            continue

        meta = comm.get("metadata", {})
        src_port = meta.get("src_port")
        dst_port = meta.get("dst_port")
        if not src_port or not dst_port:
            continue

        src_asset = state.assets.get(comm["src_asset_id"])
        dst_asset = state.assets.get(comm["dst_asset_id"])
        # Skip broadcast endpoints entirely
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

        # Outbound rule (from source host perspective)
        rows_by_host.setdefault(src_ip, []).append([
            src_label,
            src_ip,
            dst_label,
            dst_ip,
            proto,
            src_port,
            dst_port,
            "outbound",
        ])

        # Inbound rule (from destination host perspective)
        rows_by_host.setdefault(dst_ip, []).append([
            dst_label,
            dst_ip,
            src_label,
            src_ip,
            proto,
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
