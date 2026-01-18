# 🐟 Guppy ICS

**Guppy ICS** is a free, open-source, passive Industrial Control System (ICS)
network analysis tool.

It analyzes PCAP files to discover:
- assets (PLCs, IO devices, HMIs, engineering stations)
- communications between assets
- network topology
- transport-level firewall rules

Guppy ICS is inspired by tools like GrassMarlin, but built with a modern
Python architecture and extensibility in mind.

---

##Features

- Passive PCAP analysis (no active probing)
- Asset discovery (IP, MAC, role inference)
- Protocol support:
  - PROFINET IO
  - S7comm (ISO-on-TCP)
  - Modbus TCP
  - OPC UA
  - IEC 60870-5-104
- Automatic identity linking (MAC ↔ IP)
- Logical topology generation
- Firewall rule export (CSV)
- Web UI (FastAPI + Jinja2)

---

## Getting Started

### 1️⃣ Clone the repository

```bash
git clone https://github.com/<your-username>/guppy-ics.git
cd guppy-ics

python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

pip install -r requirements.txt

python -m uvicorn guppy_ics.web.app:app --reload

http://127.0.0.1:8000

Firewall Rule Export

After analyzing a PCAP, firewall rules can be downloaded as CSV.
Rules are grouped per host and can be used as input for host-based
or network firewall configuration.

Disclaimer

Guppy ICS performs passive analysis only.
It does not send any packets or modify the network.

This tool is intended for:

documentation

analysis

security assessment

learning and research

License see licence in Repo

#########################################################################
Command Line Interface (CLI)

Guppy ICS provides a full-featured command line interface (CLI) in addition to the browser-based UI.
The CLI is designed for:

Headless operation (SSH, sensors, jump hosts)

Offline PCAP analysis

Live passive network monitoring

Report generation

Firewall rule generation

Installation (CLI)

Requirements:

Python 3.9 or newer

Packet capture privileges for live mode (root / Administrator)

Supported OS:

Linux (full support)

macOS (PCAP replay, limited live capture)

Windows (PCAP replay)

#-----------------------------------------------------------------------------------

Install from source (recommended)

Clone the repository and install Guppy ICS in editable mode:

git clone https://github.com/Retep1972/guppy-ics.git

cd guppy-ics
pip install -e .

This installs the guppy command and keeps local changes active (ideal for development and sensor deployments).

Verify installation:

guppy --help

CLI Overview

guppy
├─ replay Analyze a PCAP file
├─ live Live passive network monitoring
└─ firewall Generate firewall rules

Get help at any level:

guppy --help
guppy replay --help
guppy live --help
guppy firewall --help

PCAP Replay Mode

Replay mode analyzes an existing PCAP file and generates assets, communications, and topology.

Basic replay:

guppy replay capture.pcap

Limit protocols (recommended for ICS environments):

guppy replay capture.pcap --protocol profinet --protocol s7comm

Limit packets (faster testing):

guppy replay capture.pcap --limit 5000

Output formats

Text output (default):

guppy replay capture.pcap

JSON output (machine-readable):

guppy replay capture.pcap --format json

Write output to file:

guppy replay capture.pcap --out report.txt
guppy replay capture.pcap --format json --out report.json

Section filtering

Show only assets:

guppy replay capture.pcap --only assets

Show only communications:

guppy replay capture.pcap --only comms

Show only topology:

guppy replay capture.pcap --only topology

Live Monitoring Mode

Live mode performs passive network monitoring on a network interface and periodically renders results.

WARNING: Live capture requires packet capture privileges (root / Administrator).

Live asset discovery:

guppy live assets --iface eth0

Shows:

PLCs, HMIs, IO devices, servers

Identifiers (IP / MAC)

Roles, vendors, and detected protocols

Live communications:

guppy live comms --iface eth0

Shows:

Who communicates with whom

Application-layer protocols (Profinet, S7comm, Modbus, etc.)

Ports and communication metadata

Transport-level noise filtered out

Live topology:

guppy live topology --iface eth0

Shows:

Logical topology derived from observed communications

Directional, protocol-aware edges

Application context (protocol / port / function)

Common live options

--protocol <name>
Limit analysis to specific protocols (repeatable)

--bpf <filter> specifies a Berkeley Packet Filter (BPF) expression that is applied during packet capture
It allows you to limit which packets are captured before they are processed by Guppy, reducing noise and CPU load
Apply a BPF capture filter (example: "tcp port 102")

--interval <seconds>
Refresh interval in seconds (default: 5)

--once
Render a single snapshot and exit

--out <file>
Write snapshot output to a file

#---------------------------------------------------------------------------------------

Example:

guppy live topology --iface eth0 --protocol profinet --interval 10 --out topology.txt

Firewall Rule Generation

Guppy can generate firewall intent directly from observed traffic.

Generate firewall rules as CSV:

guppy firewall csv capture.pcap

Default output file:

firewall_rules.csv

Custom output file:

guppy firewall csv capture.pcap --out profinet_rules.csv

Firewall CSV format

source,destination,protocol,transport,src_port,dst_port,service,comment

Example:

192.168.0.10,192.168.0.20,profinet,udp,,34964,,plc → io-device
192.168.0.5,192.168.0.10,s7comm,tcp,,102,ReadVar,hmi → plc

The CSV can be:

Reviewed manually

Imported into Excel

Converted to iptables / nftables / vendor ACLs

Used for rule diffing and audits

Notes and Limitations

Live mode is passive only (no packet injection)

Topology is logical, not physical switch layout

Firewall output represents observed intent, not enforcement policy

Windows live capture depends on capture backend support