# OADS Observation Coverage

Audit baseline: current local OADS README and reference rules.

| Protocol | OADS high-value fields | Guppy extracts/sends | Status | Gap |
| --- | --- | --- | --- | --- |
| MAC/OUI | `mac` | MAC identifiers when observed through L2/L3 linking | SUPPORTED | None for OUI correlation. |
| S7Comm/S7CommPlus | `order_number`, `mlfb`, `firmware_version`, `hardware_version`, `serial_number` | protocol presence, ports, functions | NOT POSSIBLE FROM CURRENT PARSER | Current parser only identifies S7comm traffic by TCP/102; it does not parse S7 identity payloads. |
| PROFINET DCP/GSDML | `station_name`, `manufacturer_id`, `vendor_id`, `device_id`, `order_number`, module/submodule IDs | `station_name`, protocol presence, frame ID | PARTIAL | DCP option parsing currently extracts station name only. Vendor/device/module IDs need deeper DCP/PNIO decoding. |
| EtherNet/IP/CIP | `vendor_id`, `device_type`, `product_code`, `revision`, `serial_number`, `product_name`, `status` | none | MISSING | No EtherNet/IP/CIP parser yet. Small path: parse TCP/UDP 44818 encapsulation and Identity Object responses. |
| OPC UA | `namespace_uri`, manufacturer/product/software/build fields | protocol presence and ports | PARTIAL | Current parser detects OPC UA traffic but does not decode UA service payloads or NamespaceArray. |
| DNP3 | Group 0 device attributes, addresses, function codes | protocol presence, direction, ports | PARTIAL | Current parser detects DNP3/UDP 20000 only; no DNP3 link/application decoding. |
| SNMP | `sysObjectID`, `sysDescr`, `sysName`, `sysLocation`, `sysContact` | protocol presence/version/ports | PARTIAL | Scapy SNMP layer is present but Guppy does not yet walk varbinds into OADS fields. |
| HTTP | `server`, `title`, `www_authenticate`, `location`, `user_agent` | these fields from visible HTTP payloads | SUPPORTED | No TCP stream reassembly beyond packet payloads. |
| DHCPv4 | hostname, FQDN, vendor class, client ID, requested/assigned IP, message type, parameter request list | DHCP client MAC/IP identity links plus raw option evidence | SUPPORTED | DHCPv6 extraction is not implemented yet. |
| DNS / LLMNR / mDNS | queries, response names, A/AAAA/PTR/SRV/TXT-style records where Scapy exposes them | DNS-like question and answer records, with LLMNR/mDNS protocol separation | PARTIAL | Does not infer hostnames from queries; DNS-SD service normalization is still shallow. |
| NetBIOS | names, suffix/type, datagram/name-service behavior | UDP/137 and UDP/138 evidence, DNS-shaped NBNS questions when Scapy exposes them | PARTIAL | Full NetBIOS suffix/role decoding is not implemented yet. |
| SSDP/UPnP | `server`, `usn`, `st`, `nt`, `location`, `host`, `cache-control` | bounded header extraction from visible SSDP payloads | SUPPORTED | Payload body parsing is not implemented. |
| ONVIF / WS-Discovery | `manufacturer`, `model`, `firmware_version`, `serial_number`, `hardware_id`, `Types`, `Scopes`, `XAddrs`, message IDs | ONVIF HTTP/XML markers, WS-Discovery fields, GetDeviceInformation response fields | SUPPORTED | Only visible/unencrypted XML payloads; HTTPS ONVIF cannot be decoded passively. |
| RTSP | `server`, `media_type`, `session`, `request_uri`, `user_agent` | RTSP control/media presence, request URI, server, session, user agent, media type | SUPPORTED | RTP codec details are not decoded beyond generic video media hint. |
| Generic TCP/UDP | ports, scope, packet/byte counts, MAC/IP endpoints, first/last seen | bounded per-flow service observations | SUPPORTED | No TCP stream reassembly; service inference remains in OADS. |
| Windows: NTLM/Kerberos/SMB/RDP | workstation/domain/realm/SPN/dialect/native OS/hostname/vendor class | none | MISSING | No SMB/NTLM/Kerberos/RDP parsers yet. |
| TLS | certificate CN/SAN/org/issuer/fingerprint | none | MISSING | No TLS certificate parser yet. |
| SSH | `server_banner`, `client_banner` | none | MISSING | No SSH banner parser yet. |
| LLDP | chassis/port/system/management/capabilities/OUI TLVs | none | MISSING | No LLDP parser yet. |
| BACnet | `vendor_id` if supported by OADS | none | MISSING | No BACnet parser yet. |

Payload semantics:

- Guppy submits OADS observations as `source`, `capture_id`, and an `observations` list.
- Each observation includes `timestamp`, `mac`, `ip`, `protocol`, `field`, `value`, and `raw_context`.
- Communication-derived observations now include `source_port`, `destination_port`, `transport`, and `function` in `raw_context` when available.
- Discovery and transport evidence is serialized as additional observations using the same OADS `field`/`value` envelope, with `evidence_type` and asset provenance in `raw_context`.
- Broadcast, multicast, unspecified, and obvious subnet-directed broadcast addresses are tracked separately from ordinary discovered assets.
- Guppy does not submit inferred `vendor`, `model`, `device_type`, `os`, or `confidence` values as authoritative facts.
