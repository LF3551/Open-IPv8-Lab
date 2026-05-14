# Roadmap

## v0.1 — Addressing core

- [x] IPv8Address class
- [x] ASN to prefix conversion
- [x] Prefix to ASN conversion
- [x] Address validation
- [x] CLI command: `ipv8lab addr`
- [x] Unit tests

## v0.2 — Packet format

- [x] IPv8 Lab packet structure
- [x] Packet serialization
- [x] Packet parsing
- [x] CRC32 checksum
- [x] CLI command: `ipv8lab packet`
- [x] Unit tests

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
- [x] Unit tests (transport + UDP runner)

## v0.6 — Developer tooling

- [x] Packet hex dump utility (`ipv8lab packet dump`)
- [x] JSON output mode (`--json` flag)
- [x] Address summary JSON
- [x] Packet summary JSON
- [x] Mypy type checking in CI
- [x] More unit tests (dump, hexdump, summaries)

## v0.7 — Mesh, capture, dashboard, benchmarks, plugins

- [x] Multi-hop mesh topologies with cycle detection
- [x] Packet capture/replay (.iv8cap format)
- [x] Web UI dashboard (dark theme, JSON API)
- [x] Performance benchmarks (6 benchmarks)
- [x] Plugin system for custom protocols
- [x] Error hierarchy (IPv8LabError)

## v0.8 — draft-thain-ipv8-00 spec compliance

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
- [x] 497 tests total

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
- [x] 836 tests total
- [x] PCAP export for Wireshark integration (`ipv8lab pcap`)
- [x] 874 tests total
- [x] IPv8 packet fragmentation and reassembly (`ipv8lab frag`)
- [x] 936 tests total
- [x] Traceroute8 diagnostic utility (`ipv8lab traceroute`)
- [x] 1220 tests total

## Future

- [x] NAT8 address translation gateway simulation
- [x] Flow monitoring and NetFlow8-style telemetry export
- [x] QoS / traffic shaping based on TOS field
- [x] Docker-based multi-node testbed
- [ ] TUI dashboard (Rich Live / Textual)
- [ ] Packet fuzzer for protocol security testing
- [ ] mTLS / encryption layer for Zone Server auth
- [ ] PyPI package publishing
