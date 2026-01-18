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