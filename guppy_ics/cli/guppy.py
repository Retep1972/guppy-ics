from __future__ import annotations

import argparse
import json
from pathlib import Path

from guppy_ics.analysis.run import analyze_pcap
from guppy_ics.core.sources.pcap import PcapFileSource
from guppy_ics.core.sources.live import LiveInterfaceSource
from guppy_ics.analysis.run import analyze_source



def cmd_ingest(args) -> int:
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

    print()

    print("\n=== Guppy ICS Summary ===")
    print(state.summary())

    print("\n=== Assets (by IP) ===")
    # Make assets JSON-friendly (protocols is a set)
    assets_sorted = sorted(state.assets.values(), key=lambda a: a["identifier"])
    for a in assets_sorted:
        a = dict(a)
        a["protocols"] = sorted(list(a["protocols"]))
        print(json.dumps(a, indent=2))

    print("\n=== Communications ===")
    comms_sorted = sorted(state.communications.values(), key=lambda c: (c["protocol"], c["count"]), reverse=True)
    for c in comms_sorted:
        print(json.dumps(c, indent=2))

    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="guppy", description="Guppy ICS (passive ICS visibility)")
    sub = p.add_subparsers(dest="command", required=True)

    ingest = sub.add_parser("ingest", help="Ingest a PCAP file")
    ingest.add_argument("pcap", help="Path to .pcap/.pcapng")
    ingest.add_argument("--protocol", action="append", help="Enable only these protocols (repeatable), e.g. --protocol modbus")
    ingest.add_argument("--limit", type=int, default=None, help="Limit number of packets processed")
    ingest.set_defaults(func=cmd_ingest)
    live = sub.add_parser("live", help="Passive live capture from an interface")
    live.add_argument("interface", help="Network interface name")
    live.add_argument("--protocol", action="append")
    live.add_argument("--bpf", default=None, help="Optional BPF filter")
    live.add_argument("--limit", type=int, default=None, help="Packet limit")
    live.add_argument("--timeout", type=int, default=None, help="Capture timeout (seconds)")
    live.set_defaults(func=cmd_live)

    return p

def cmd_live(args) -> int:
    source = LiveInterfaceSource(
        interface=args.interface,
        bpf_filter=args.bpf,
        packet_limit=args.limit,
        timeout=args.timeout,
    )

    state = analyze_source(
        source,
        enabled_protocols=args.protocol,
    )

    print("\n=== Live Capture Summary ===")
    print(state.summary())
    return 0

def cli_progress(count: int):
    print(f"\rProcessed {count} packets...", end="", flush=True)

def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
