# 🐟 Guppy ICS

**Guppy ICS** is a free, open-source, passive Industrial Control System (ICS)
network analysis tool.

It analyzes PCAP files and live traffic to discover:

- Assets (PLCs, IO devices, HMIs, engineering stations)
- Communications between assets
- Logical network topology
- Transport-level firewall intent

Guppy ICS is inspired by tools like GrassMarlin, but built with a modern,
extensible Python architecture and designed for both OT engineers and
security practitioners.

---

## Features

- Passive analysis (no active probing)
- PCAP replay and live capture
- Asset discovery (IP, MAC, role inference)
- Protocol support:
  - PROFINET IO
  - S7comm (ISO-on-TCP)
  - Modbus TCP
  - HTTP banners and metadata
  - ONVIF / RTSP cameras
  - SIP, SDP, RTP/RTCP, IGMP, and PTP network-audio evidence
  - LLDP and Cisco Discovery Protocol switch identity
  - OPC UA
  - IEC 60870-5-104
  - DHCP, DNS, LLMNR, mDNS, NetBIOS, SSDP, and WS-Discovery evidence
- Automatic identity linking (MAC ↔ IP)
- Conservative handling of broadcast, multicast, and special addresses
- Logical topology generation
- Firewall rule generation (CSV)
- Web UI (FastAPI)
- Command Line Interface (CLI)

---

## Installation

### Requirements

- Python **3.9+**
- Packet capture privileges for live mode (root / Administrator)
- Supported platforms:
  - Linux (full support)
  - macOS (PCAP replay, limited live capture)
  - Windows (PCAP replay)

---

### Install from source (recommended)

```bash
git clone https://github.com/Retep1972/guppy-ics.git
cd guppy-ics

python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

pip install -e .
```

Verify installation:

```bash
guppy --help
```

---

## Starting Guppy ICS

Running `guppy` without arguments starts an interactive launcher menu.

```bash
guppy
```

You will be presented with:

```
Guppy ICS
==========
1) Browser (Web UI)
2) Command Line Interface (CLI)
q) Quit
```

### Browser (Web UI)

Select option **1** to start the web interface.

The Web UI will be available at:

```
http://127.0.0.1:8002
```

Stop the server with **Ctrl-C**.

The upload page does not preselect protocol checkboxes. If no protocols are
selected, Guppy analyzes all available protocols. Select one or more protocols
only when you want to limit analysis.

The result page includes an **Evidence details** section for passive discovery
evidence such as DHCP hostnames, DNS/LLMNR queries, SSDP headers, WS-Discovery
XML fields, and generic TCP/UDP service observations. Broadcast and multicast
addresses are tracked as infrastructure/special addresses and are not shown as
ordinary assets.

### Command Line Interface (CLI)

Select option **2** to open the CLI help, or skip the menu entirely by
calling CLI commands directly.

Example (skip menu):

```bash
guppy replay capture.pcap
```

This behavior makes Guppy suitable for both interactive use and automation.

---

## CLI Overview

```text
guppy
 ├─ replay     Analyze a PCAP file
 ├─ live       Live passive network monitoring
 └─ firewall   Generate firewall rules
```

Get help at any level:

```bash
guppy --help
guppy replay --help
guppy live --help
guppy firewall --help
```

---

## PCAP Replay Mode

Replay mode analyzes an existing PCAP file and generates assets,
communications, and topology.

Basic replay:

```bash
guppy replay capture.pcap
```

Limit protocols (recommended for ICS environments):

```bash
guppy replay capture.pcap --protocol profinet --protocol s7comm
```

Limit packets (faster testing):

```bash
guppy replay capture.pcap --limit 5000
```

### Output formats

Text output (default):

```bash
guppy replay capture.pcap
```

JSON output (machine-readable):

```bash
guppy replay capture.pcap --format json
```

Write output to file:

```bash
guppy replay capture.pcap --out report.txt
guppy replay capture.pcap --format json --out report.json
```

### Section filtering

```bash
guppy replay capture.pcap --only assets
guppy replay capture.pcap --only comms
guppy replay capture.pcap --only topology
```

---

## Live Monitoring Mode

Live mode performs **continuous, passive monitoring** of a network interface.
Results update incrementally as traffic is observed and are rendered at a
configurable interval.

Live mode uses the **same analysis pipeline** as PCAP replay and the Web UI,
ensuring consistent results across all interfaces.

**Important notes:**
- Live mode is designed for *situational awareness*, not deep packet inspection.
- Background IT noise (multicast, IPv6 chatter, broadcast traffic) is filtered
  automatically.
- Only assets with meaningful, observed behavior are shown by default.

**Warning:** Live capture requires packet capture privileges
(root / Administrator).

### Live assets

```bash
guppy live assets --iface eth0
```

Shows discovered devices, identifiers, roles, vendors, and protocols.

### Live communications

```bash
guppy live comms --iface eth0
```

Shows who communicates with whom, including application protocols and ports.
Low-level transport noise is filtered out.

### Live topology

```bash
guppy live topology --iface eth0
```

Shows a logical, protocol-aware topology derived from observed traffic.

### Common live options

```text
--protocol <name>     Limit analysis to specific protocols (repeatable)
--bpf <filter>        Berkeley Packet Filter applied at capture time
--interval <seconds>  Refresh interval (default: 5)
--once                Render a single snapshot and exit
--out <file>          Write output to a file
```

Example:

```bash
guppy live topology --iface eth0 --protocol profinet --interval 10 --out topology.txt
```

---

### Live PCAP Simulation Mode (Testing / Demo)

Guppy ICS also supports replaying a PCAP file **as if it were live network traffic**.
This mode is intended for:

- Testing the *live analysis pipeline*
- Demonstrations and training
- Development without access to a real ICS network
- Portable setups (e.g. laptops, Raspberry Pi)

In this mode, packets are read from a PCAP file and injected into the live
analysis pipeline with their original timing preserved.

> From Guppy’s perspective, this is indistinguishable from real live traffic.

No network interface is required, and no packets are sent onto the wire.

#### Live PCAP assets

```bash
guppy live assets --pcap capture.pcap
guppy live comms --pcap capture.pcap
guppy live topology --pcap capture.pcap
```

#### Timing control

Replay speed can be adjusted:

```bash
guppy live assets --pcap capture.pcap --speed 0.5   # half speed
guppy live assets --pcap capture.pcap --speed 2.0   # double speed
```

Loop a capture continuously:

```bash
guppy live topology --pcap capture.pcap --loop
```

## OADS Enrichment

OADS is the OT Asset Discovery Service: a REST backend for passive OT asset
discovery from PCAP-derived observations. It runs as a local Docker Compose
appliance. Guppy connects to that local OADS HTTP API and retrieves enriched
asset profiles from it.

Get OADS in a separate directory and follow its README:

```bash
git clone git@github.com:Retep1972/oads.git
cd oads
```

Guppy can optionally submit passive PCAP-derived observations to a local OADS
Docker Compose instance, then fetch enriched asset profiles.

Start OADS separately, then check:

```bash
curl http://localhost:8000/health
```

Use the Web UI upload page and enable **OADS enrichment**, or run:

```bash
guppy replay capture.pcap --oads-enhance
```

The default OADS URL is:

```text
http://localhost:8000
```

Override it with:

```bash
guppy replay capture.pcap --oads-enhance --oads-url http://localhost:8000
```

Environment variables:

```text
GUPPY_OADS_ENABLED=true
GUPPY_OADS_URL=http://localhost:8000
GUPPY_OADS_TIMEOUT=5
GUPPY_OADS_MAX_OBSERVATIONS=1500
GUPPY_OADS_BATCH_SIZE=100
GUPPY_OADS_SKIP_KNOWN_ASSETS=true
```

The local OADS Docker API does not require an API key.

Guppy checks OADS health and fetches the current OADS asset list before
submitting observations. If OADS already knows an asset by MAC or IP, Guppy
skips reposting observations for that asset by default and attaches the
existing OADS profile instead. This avoids overloading OADS with repeated
evidence for already-known assets.

Observation submits are batched. If a batch times out or fails, Guppy logs or
shows a warning and continues local analysis output. In the Web UI, **OADS
details** shows health status, asset preflight status, total observations
built, skipped known observations, observations POSTed, and how many were
accepted before a failure.

Guppy sends passive evidence only. Current evidence includes asset identifiers,
generic TCP/UDP service observations, DHCP host/vendor options, DNS/LLMNR/mDNS
records, NetBIOS service evidence, SSDP headers, WS-Discovery XML fields,
HTTP/ONVIF/RTSP metadata, LLDP/CDP switch identity fields, SIP/SDP/RTP/RTCP
network-audio observations, IGMP multicast membership, PTP timing evidence, and
OT protocol observations where Guppy can parse raw values. OADS remains
responsible for vendor, model, device type, OS, and confidence inference.

Communications and topology prefer the most specific observed protocol. For
example, if Modbus TCP is detected, Guppy shows the communication as `modbus`
and suppresses a duplicate generic `tcp` row for the same asset pair and
service port. Generic `tcp` or `udp` rows are still shown when no more specific
protocol parser matched.

Current field-level coverage is tracked in
[`docs/oads_coverage.md`](docs/oads_coverage.md).

## Firewall Rule Generation

Guppy can generate firewall intent directly from observed traffic.

Generate firewall rules as CSV:

```bash
guppy firewall csv capture.pcap
```

Default output:

```
firewall_rules.csv
```

Custom output:

```bash
guppy firewall csv capture.pcap --out profinet_rules.csv
```

### Firewall CSV format

```csv
source,destination,protocol,transport,src_port,dst_port,service,comment
```

Example:

```csv
192.168.0.10,192.168.0.20,profinet,udp,,34964,,plc → io-device
192.168.0.5,192.168.0.10,s7comm,tcp,,102,ReadVar,hmi → plc
```

The CSV can be:
- Reviewed manually
- Imported into Excel
- Converted to firewall rules
- Used for audits and rule diffing

---

## Notes and Limitations

- Guppy performs **passive analysis only** — it never sends packets into the network.
- Asset discovery is **best-effort inference** based on observed traffic.
- Background IT noise (multicast, IPv6 discovery, broadcast traffic) is filtered
  to keep output focused on ICS-relevant devices.
- Topology is logical and protocol-aware, not a physical wiring diagram.
- Firewall output reflects **observed communication intent**, not a complete
  security policy.
- Live capture reliability depends on OS capture backend support
  (libpcap / Npcap).
- On Windows, live capture requires a compatible Npcap installation.

---

## License

See LICENSE file in the repository.
