from __future__ import annotations

import argparse, time, os, signal
import json, csv
from dataclasses import is_dataclass, asdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from guppy_ics.analysis.run import analyze_pcap, analyze_source
from guppy_ics.core.sources.live import LiveInterfaceSource
from collections import defaultdict

TRANSPORT_PROTOCOLS = {"ip", "ipv4", "ipv6", "tcp", "udp"}

# ----------------------------
# Rendering helpers
# ----------------------------
def filter_communications_for_ui(communications: List[dict]) -> List[dict]:
    """
    Collapse protocol stacks for UI presentation.
    Rules:
    - Prefer application protocols over transport (ip/tcp/udp)
    - Fallback to tcp/udp if no application protocol exists
    - Never show pure IP
    """
    flows = defaultdict(list)

    for c in communications:
        meta = c.get("metadata", {}) or {}
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

        # 1) Prefer non-transport (application) protocols
        for c in comms:
            if (c.get("protocol") or "").lower() not in TRANSPORT_PROTOCOLS:
                selected = c
                break

        # 2) Fallback to tcp/udp
        if not selected:
            for c in comms:
                if (c.get("protocol") or "").lower() in {"tcp", "udp"}:
                    selected = c
                    break

        # 3) Never show pure IP
        if selected:
            filtered.append(selected)

    return filtered

def build_topology_from_communications(communications: List[dict], state: Any) -> Dict[str, List[str]]:
    """
    Build adjacency lists (topology) from communications already filtered for UI.
    """

    def asset_display(asset: Optional[dict]) -> str:
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

    topology: Dict[str, set] = {}

    for c in communications:
        src_asset = state.assets.get(c.get("src_asset_id"))
        dst_asset = state.assets.get(c.get("dst_asset_id"))

        src_disp = asset_display(src_asset)
        dst_disp = asset_display(dst_asset)

        proto = c.get("protocol", "unknown")
        func = c.get("function")
        meta = c.get("metadata", {}) or {}

        label_parts = [proto]
        if func:
            label_parts.append(str(func))
        if "dst_port" in meta:
            label_parts.append(f"port {meta['dst_port']}")

        edge_label = " / ".join(label_parts)

        topology.setdefault(src_disp, set()).add(f"{edge_label} → {dst_disp}")

    # normalize for rendering
    return {k: sorted(v) for k, v in topology.items()}

def _asset_label_by_id(state: Any) -> Dict[str, str]:
    """
    Map asset_id -> nice display string (identifier, role/vendor if you want).
    """
    assets = _extract_assets(state)
    mapping = {}
    for a in assets:
        aid = a.get("asset_id")
        ident = a.get("identifier") or aid or "-"
        if aid:
            mapping[str(aid)] = str(ident)
    return mapping

def _to_plain(obj: Any) -> Any:
    """Convert dataclasses/sets/etc into JSON-safe python objects."""
    if is_dataclass(obj):
        obj = asdict(obj)
    if isinstance(obj, dict):
        return {k: _to_plain(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_plain(v) for v in obj]
    if isinstance(obj, set):
        return sorted([_to_plain(v) for v in obj])
    return obj


def _badge_list(protocols: Iterable[str]) -> str:
    # simple “badges” for terminal
    prots = [p for p in protocols if p]
    return " ".join(f"[{p}]" for p in prots) if prots else "-"


def _table(rows: List[List[str]], headers: List[str]) -> str:
    """Small dependency-free table renderer."""
    cols = len(headers)
    widths = [len(h) for h in headers]
    for r in rows:
        for i in range(cols):
            widths[i] = max(widths[i], len(r[i]) if i < len(r) else 0)

    def fmt_row(r: List[str]) -> str:
        r = (r + [""] * cols)[:cols]
        return " | ".join((r[i] or "").ljust(widths[i]) for i in range(cols))

    sep = "-+-".join("-" * w for w in widths)
    out = [fmt_row(headers), sep]
    out += [fmt_row(r) for r in rows]
    return "\n".join(out)


def _extract_assets(state: Any) -> List[Dict[str, Any]]:
    assets = getattr(state, "assets", {}) or {}
    # state.assets often dict of asset_id->asset or identifier->asset; we handle both.
    vals = list(assets.values()) if isinstance(assets, dict) else list(assets)
    out = []
    for a in vals:
        a = _to_plain(a)
        if isinstance(a, dict):
            out.append(a)
    # stable sort by identifier if present
    out.sort(key=lambda x: str(x.get("identifier", "")))
    return out


def _extract_comms(state: Any) -> List[Dict[str, Any]]:
    comms = getattr(state, "communications", {}) or {}
    vals = list(comms.values()) if isinstance(comms, dict) else list(comms)
    out = []
    for c in vals:
        c = _to_plain(c)
        if isinstance(c, dict):
            out.append(c)
    # sort: protocol then count desc if present
    out.sort(key=lambda x: (str(x.get("protocol", "")), -int(x.get("count", 0) or 0)))
    return out

def render_report_text(state: Any, only: str = "all") -> str:
    parts: List[str] = []

    parts.append("=== Guppy ICS Summary ===")
    summary = getattr(state, "summary", None)
    if callable(summary):
        summary_val = summary()
    else:
        summary_val = getattr(state, "summary", "n/a")

    # Force summary to text
    if isinstance(summary_val, dict):
        parts.append(json.dumps(summary_val, indent=2))
    else:
        parts.append(str(summary_val))

    if only in ("all", "assets"):
        assets = _extract_assets(state)
        parts.append("=== Assets ===")
        rows = []
        for a in assets:
            ident = str(a.get("identifier", "-"))
            itype = str(a.get("identifier_type", "-"))
            role = str(a.get("role", "-") or "-")
            vendor = str(a.get("vendor", "-") or "-")
            prots = a.get("protocols", []) or []
            rows.append([ident, itype, role, vendor, _badge_list(prots)])
        parts.append(_table(rows, headers=["Identifier", "Type", "Role", "Vendor", "Protocols"]))
        parts.append("")

    if only in ("all", "comms"):
        comms_raw = _extract_comms(state)

        # Match browser behavior
        comms = filter_communications_for_ui(comms_raw)

        # Resolve asset ids to identifiers for src/dst
        labels = _asset_label_by_id(state)

        parts.append("=== Communications ===")
        rows = []
        if not comms:
            parts.append("(no industrial communications observed)")
        else:
            for c in comms:
                proto = str(c.get("protocol", "-"))

                src_id = c.get("src_asset_id")
                dst_id = c.get("dst_asset_id")

                src = labels.get(str(src_id), str(src_id or "-"))
                dst = labels.get(str(dst_id), str(dst_id or "-"))

                meta = c.get("metadata", {}) or {}
                src_port = meta.get("src_port", "-")
                dst_port = meta.get("dst_port", "-")

                # optional: packet/byte counts if present
                count = c.get("count", c.get("packets", "-"))

                rows.append([proto, src, str(src_port), dst, str(dst_port), str(count)])

            parts.append(_table(rows, headers=["Protocol", "Source", "S.Port", "Destination", "D.Port", "Count"]))
            parts.append("")


    if only in ("all", "topology"):
        comms_raw = _extract_comms(state)
        comms = filter_communications_for_ui(comms_raw)

        topology = build_topology_from_communications(comms, state)

        parts.append("=== Topology ===")

        if not topology:
            parts.append("(no topology could be derived from communications)")
        else:
            for src, edges in topology.items():
                parts.append(f"{src}")
                for e in edges:
                    parts.append(f"  └─ {e}")

        parts.append("")

    return "\n".join(parts).rstrip() + "\n"

def render_report_json(state: Any, only: str = "all") -> str:
    payload: Dict[str, Any] = {}

    summary = getattr(state, "summary", None)
    payload["summary"] = summary() if callable(summary) else _to_plain(summary)

    comms_raw = _extract_comms(state)
    comms = filter_communications_for_ui(comms_raw)

    if only in ("all", "assets"):
        payload["assets"] = _extract_assets(state)

    if only in ("all", "comms"):
        payload["communications"] = comms

    if only in ("all", "topology"):
        payload["topology"] = build_topology_from_communications(comms, state)

    return json.dumps(payload, indent=2) + "\n"

# ----------------------------
# Commands
# ----------------------------

def cli_progress(count: int):
    print(f"\rProcessed {count} packets...", end="", flush=True)


def cmd_replay(args) -> int:
    pcap_path = Path(args.pcap)
    if not pcap_path.exists():
        print(f"ERROR: PCAP not found: {pcap_path}")
        return 2

    enabled = args.protocol if args.protocol else None
    state = analyze_pcap(
        str(pcap_path),
        enabled_protocols=enabled,
        limit=args.limit,
        progress_cb=cli_progress,
    )
    print()  # end progress line

    if args.format == "json":
        report = render_report_json(state, only=args.only)
    else:
        report = render_report_text(state, only=args.only)

    # terminal output
    print(report, end="")

    # optional file output
    if args.out:
        out_path = Path(args.out)
        out_path.write_text(report, encoding="utf-8")
        print(f"\n[+] Wrote report: {out_path}")

    return 0

def cmd_firewall_csv(args) -> int:
    state = analyze_pcap(
        args.pcap,
        enabled_protocols=args.protocol,
        limit=args.limit,
    )

    rules = generate_firewall_rules(state)
    write_firewall_csv(rules, args.out)

    print(f"[+] Generated {len(rules)} firewall rules")
    print(f"[+] Output written to {args.out}")
    return 0

def cmd_live_assets(args):
    def render(state):
        return render_report_text(state, only="assets")
    run_live(args, render)

def cmd_live_comms(args):
    def render(state):
        return render_report_text(state, only="comms")
    run_live(args, render)

def cmd_live_topology(args):
    def render(state):
        return render_report_text(state, only="topology")
    run_live(args, render)

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="guppy", description="Guppy ICS (passive ICS visibility)")
    sub = p.add_subparsers(dest="command", required=True)

    replay = sub.add_parser("replay", help="Replay a PCAP and generate a report")
    replay.add_argument("pcap", help="Path to .pcap/.pcapng")
    replay.add_argument("--protocol", action="append", help="Enable only these protocols (repeatable)")
    replay.add_argument("--limit", type=int, default=None, help="Limit number of packets processed")
    replay.add_argument("--only", choices=["all", "assets", "comms", "topology"], default="all",
                        help="Only render a specific section")
    replay.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    replay.add_argument("--out", default=None, help="Write report to a file (e.g. report.txt)")
    replay.set_defaults(func=cmd_replay)

    # Old. check if anything breaks
    #ingest = sub.add_parser("ingest", help="(alias) Replay a PCAP and generate a report")
    #ingest.add_argument("pcap", help="Path to .pcap/.pcapng")
    #ingest.add_argument("--protocol", action="append", help="Enable only these protocols (repeatable)")
    #ingest.add_argument("--limit", type=int, default=None, help="Limit number of packets processed")
    #ingest.add_argument("--only", choices=["all", "assets", "comms", "topology"], default="all")
    #ingest.add_argument("--format", choices=["text", "json"], default="text")
    #ingest.add_argument("--out", default=None)
    #ingest.set_defaults(func=cmd_replay)

    live = sub.add_parser("live", help="Passive live capture from an interface")
    live_sub = live.add_subparsers(
        dest="live_cmd",
        required=True
    )
    def add_live_common(p):
        p.add_argument("--iface", required=True, help="Network interface to capture from")
        p.add_argument("--protocol", action="append", help="Limit analysis to specific protocols")
        p.add_argument("--bpf", help="Optional BPF capture filter")
        p.add_argument("--interval", type=int, default=5, help="Refresh interval in seconds")
        p.add_argument("--once", action="store_true", help="Render a single snapshot and exit")
        p.add_argument("--out", help="Write output to a file")

    assets = live_sub.add_parser("assets", help="Show discovered assets")
    add_live_common(assets)
    assets.set_defaults(func=cmd_live_assets)

    comms = live_sub.add_parser("comms", help="Show communications")
    add_live_common(comms)
    comms.set_defaults(func=cmd_live_comms)

    topo = live_sub.add_parser("topology", help="Show topology")
    add_live_common(topo)
    topo.set_defaults(func=cmd_live_topology)

    #firewall rules
    fw = sub.add_parser("firewall", help="Generate firewall rules")
    fw_sub = fw.add_subparsers(
        dest="firewall_cmd",
        required=True
    )

    csv_cmd = fw_sub.add_parser("csv", help="Generate firewall rules as CSV")
    csv_cmd.add_argument("pcap", help="PCAP to analyze")
    csv_cmd.add_argument("--out", default="firewall_rules.csv")
    csv_cmd.add_argument("--protocol", action="append")
    csv_cmd.add_argument("--limit", type=int)
    csv_cmd.set_defaults(func=cmd_firewall_csv)
    return p

### Helper for csv firewall file
def write_firewall_csv(rules: Iterable[dict], path: str):
    fieldnames = [
        "source",
        "destination",
        "protocol",
        "transport",
        "src_port",
        "dst_port",
        "service",
        "comment",
    ]

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in rules:
            writer.writerow(r)

def generate_firewall_rules(state: Any) -> List[dict]:
    """
    Generate firewall rules from UI-filtered communications.
    """
    comms_raw = _extract_comms(state)
    comms = filter_communications_for_ui(comms_raw)

    # asset_id -> asset
    assets = state.assets

    rules = []
    seen = set()

    for c in comms:
        src = assets.get(c.get("src_asset_id"))
        dst = assets.get(c.get("dst_asset_id"))

        if not src or not dst:
            continue

        src_ids = src.get("identifiers", {})
        dst_ids = dst.get("identifiers", {})

        src_ip = next(iter(sorted(src_ids.get("ip", []))), None)
        dst_ip = next(iter(sorted(dst_ids.get("ip", []))), None)

        if not src_ip or not dst_ip:
            continue

        meta = c.get("metadata", {}) or {}

        transport = meta.get("transport")
        dst_port = meta.get("dst_port")
        src_port = meta.get("src_port")

        protocol = c.get("protocol", "unknown")
        service = c.get("function") or ""

        key = (src_ip, dst_ip, protocol, transport, src_port, dst_port)
        if key in seen:
            continue
        seen.add(key)

        rules.append({
            "source": src_ip,
            "destination": dst_ip,
            "protocol": protocol,
            "transport": transport or "",
            "src_port": src_port or "",
            "dst_port": dst_port or "",
            "service": service,
            "comment": f"{src.get('role','')} → {dst.get('role','')}".strip()
        })

    return rules

def _clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

def run_live(args, render_fn):
    source = LiveInterfaceSource(
        interface=args.iface,
        bpf_filter=args.bpf,
        packet_limit=None,
        timeout=None,
    )
    enabled = args.protocol if args.protocol else None

    state = analyze_source(
        source,
        enabled_protocols=enabled,
    )

    try:
        while True:
            _clear_screen()
            output = render_fn(state)

            print(output, end="")

            if args.out:
                with open(args.out, "w", encoding="utf-8") as f:
                    f.write(output)

            if args.once:
                break

            time.sleep(args.interval)

    except KeyboardInterrupt:
        print("\n[+] Live capture stopped.")

def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
