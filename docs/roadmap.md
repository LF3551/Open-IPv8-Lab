# Roadmap

## v0.1 — Addressing core

- [x] IPv8Address class
- [x] ASN to prefix conversion
- [x] Prefix to ASN conversion
- [x] Address validation
- [x] CLI command: `ipv8lab addr`

## v0.2 — Packet format

- [x] IPv8 Lab packet structure
- [x] Packet serialization
- [x] Packet parsing
- [x] CRC32 checksum
- [x] CLI command: `ipv8lab packet`

## v0.3 — Routing simulator

- [x] Route table
- [x] Route lookup
- [x] YAML config loader
- [x] Simple routing simulation
- [x] CLI command: `ipv8lab route simulate`

## v0.4 — Local testbed

- [x] Node abstraction
- [x] Router abstraction
- [x] Two-ASN demo
- [x] Packet tracing
- [x] Example scenarios

## v0.5 — UDP transport experiment

- [x] UDP framing protocol (magic + length)
- [x] Async UDP transport (send/receive)
- [x] UDP node runner with forwarding
- [x] UDP network orchestrator
- [x] CLI command: `ipv8lab udp run`
- [x] UDP demo example

## v0.6 — Developer tooling

- [x] Packet hex dump utility (`ipv8lab packet dump`)
- [x] JSON output mode (`--json` flag)
- [x] Address summary JSON
- [x] Packet summary JSON
- [x] Mypy type checking in CI

## v0.7 — Mesh, capture, dashboard, benchmarks, plugins

- [x] Multi-hop mesh topologies with cycle detection
- [x] Packet capture/replay (.iv8cap format)
- [x] Web UI dashboard (dark theme, JSON API)
- [x] Performance benchmarks (6 benchmarks)
- [x] Plugin system for custom protocols
- [x] Error hierarchy (IPv8LabError)

## v0.8 — draft-thain-ipv8-02 spec compliance

- [x] Address class classification per Section 4
- [x] Spec-compliant packet header `!BBHHHBBHIIII` per Section 5.1
- [x] Prefix validation and routing scope per Sections 3.5, 3.9, 3.10
- [x] Two-tier routing table per Section 8.7
- [x] Multicast/broadcast classification per Sections 10–12
- [x] Border router ingress filtering per Section 18
- [x] ICMPv8 protocol per Section 9
- [x] 8to4 tunnelling per Section 13.3
- [x] Device compliance tiers per Sections 17.1–17.3
- [x] NIC rate limits per Section 17.5
- [x] DNS A8 record type per Section 7
- [x] VRF per Section 8.8
- [x] PVRST per Section 17.4

## v0.9 — Management suite & companion specs

- [x] Cost Factor (CF) metric simulation per Section 1.6
- [x] WHOIS8 mock resolver (ASN validation, route validation)
- [x] DHCP8 lease simulation per Section 1.3 (single-response provisioning)
- [x] Zone Server mock (OAuth8 cache, ACL8 engine) per Sections 1.3, 1.4
- [x] NetLog8 telemetry client (SEC-ALERT, E3 traps) per Section 18
- [x] Companion spec modules:
  - [x] BGP8/IBGP8/OSPF8/IS-IS8 (draft-thain-routing-protocols-00)
  - [x] RINE peering fabric (draft-thain-rine-00)
  - [x] ARP8 with gratuitous announce (draft-thain-support8-00)
  - [x] XLATE8 translation table (draft-thain-zoneserver-00)
  - [x] Update8 and NIC certification (draft-thain-update8-00)
  - [x] WiFi8 protocol (draft-thain-wifi8-00)
  - [x] SNMPv8 MIB (draft-thain-ipv8-mib-00)

## v0.10 — Integration scenarios

- [x] End-to-end integration scenario (DHCP8 → OAuth8 → ACL8 → routing)
- [x] Multi-zone simulation with Zone Server pairs
- [x] BGP8 path selection with CF metric
- [x] XLATE8 north-south traffic flow
- [x] Interactive CLI for Zone Server management (`ipv8lab zone`)
- [x] Multi-zone CLI commands (`ipv8lab multizone`)
- [x] BGP8 path selection CLI (`ipv8lab bgp8`)
- [x] XLATE8 flow CLI (`ipv8lab xlate8`)
- [x] Performance dashboard with CF visualisation (`ipv8lab cf`)
- [x] PCAP export for Wireshark integration (`ipv8lab pcap`)
- [x] IPv8 packet fragmentation and reassembly (`ipv8lab frag`)
- [x] Traceroute8 diagnostic utility (`ipv8lab traceroute`)

## v0.11 — Security, operations & tooling

- [x] NAT8 address translation gateway simulation (`ipv8lab nat8`)
- [x] Flow monitoring and NetFlow8-style telemetry export (`ipv8lab netflow8`)
- [x] QoS / traffic shaping based on TOS field (`ipv8lab qos`)
- [x] Docker-based multi-node testbed (`ipv8lab docker`)
- [x] TUI dashboard — Rich Live / Textual (`ipv8lab tui`)
- [x] Packet fuzzer for protocol security testing (`ipv8lab fuzz`)
- [x] mTLS / encryption layer for Zone Server auth (`ipv8lab mtls`)

## Future — draft-thain-ipv8-02 compliance

- [x] ARP8-driven version selection simulation per Section 2 (neighbor discovery, per-hop IPv8/IPv4 downgrade)
- [x] Inter-Company Interop Prefix (127.127.0.0) and Two-XLATE8 Interop Model per Sections 4.6–4.7
- [x] Private Interop ASN (65534/65533) reservation per Section 4.8
- [x] Interior Link Convention (222.0.0.0/8) address validation per Section 4.10
- [x] Address Usage Model — consolidated address space table per Section 4.11
- [x] Socket API Compatibility mock (AF_INET8, sockaddr_in8) per Section 6.2
- [ ] CGNAT Behaviour simulation (r.r.r.r preservation, n.n.n.n-only NAT) per Section 15
- [ ] XLATE8 Even/Odd Load Balancing per Section 15.1
- [ ] Cloud Provider VPC simulation (zone prefix → VPC mapping) per Section 17
- [ ] RINE Prefix Protection (100.x.x.x filtering, SEC-ALERT) per Section 19.3
- [ ] Interior Link Convention Protection (222.0.0.0/8 BGP8 filtering) per Section 19.4
- [ ] /16 Minimum Prefix Enforcement at eBGP8 boundaries per Section 19.7
- [ ] Companion spec: draft-thain-whois8-00 (standalone WHOIS8 protocol)
- [ ] Companion spec: draft-thain-netlog8-00 (standalone NetLog8 protocol)
- [ ] PyPI package publishing
