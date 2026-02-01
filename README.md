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
  - OPC UA
  - IEC 60870-5-104
- Automatic identity linking (MAC ↔ IP)
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
http://127.0.0.1:8000
```

Stop the server with **Ctrl-C**.

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

--protocol <name>     Limit analysis to specific protocols (repeatable)
--bpf <filter>        Berkeley Packet Filter applied at capture time
--interval <seconds>  Refresh interval (default: 5)
--once                Render a single snapshot and exit
--out <file>          Write output to a file


Example:

guppy live topology --iface eth0 --protocol profinet --interval 10 --out topology.txt

---

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

# Notes and Limitations

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
