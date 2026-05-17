# Changelog

All notable changes to Open-IPv8-Lab are documented here.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.12.9] — 2026-05-17

### Fixed
- PyPI publish now triggers on tag push (was blocked by GITHUB_TOKEN event limitation)

### Changed
- Bumped CI actions: actions/setup-python v6, actions/checkout v6, docker/setup-buildx-action v4, docker/login-action v4, docker/build-push-action v7
- Bumped mkdocs-material to >=9.7.6

## [0.12.8] — 2026-05-15

### Changed
- Fixed release pipeline: Homebrew formula auto-update now works end-to-end

## [0.12.7] — 2026-05-15

### Changed
- Release automation now updates Homebrew formula via auto-generated pull request (compatible with protected main branch)

## [0.12.6] — 2026-05-15

### Added
- Homebrew formula in-repo (`Formula/open-ipv8-lab.rb`) for install via tap

### Changed
- Release workflow now auto-updates Homebrew formula URL and SHA256 on each tag

## [0.12.5] — 2026-05-15

### Added
- Community health files: CODEOWNERS, Code of Conduct, pull request template, and issue templates
- Release visibility enhancements: repository homepage, funding config, and social preview asset

### Changed
- PyPI metadata improved with classifiers for Python versions, license, audience, and topics
- CI uploads coverage to Codecov and README includes coverage badge

## [0.12.0] — 2026-05-15

### Added
- Interior Link Convention Protection (222.0.0.0/8 BGP8 filtering) per §19.4 — `ipv8lab ilinkprot`
- /16 Minimum Prefix Enforcement at eBGP8 boundaries per §19.7 — `ipv8lab prefixenf`
- Standalone WHOIS8 protocol (draft-thain-whois8-00): server, client, HMAC signing — `ipv8lab whois8`
- Standalone NetLog8 protocol (draft-thain-netlog8-00): wire framing, collector, relay — `ipv8lab netlog8proto`

### Fixed
- 33 broken CLI examples across documentation
- 3 broken testbed examples (UDP config, capture, dashboard)
- Navigation: all docs now have ← Back to README link

## [0.11.0] — 2026-05-14

### Added
- NAT8 address translation gateway (static/dynamic/PAT) — `ipv8lab nat8`
- NetFlow8 flow monitoring and telemetry export (.nf8 format) — `ipv8lab netflow8`
- QoS traffic shaping (priority/WFQ/FIFO, token bucket, TOS) — `ipv8lab qos`
- Docker-based multi-node testbed — `ipv8lab docker`
- TUI dashboard (Rich Live / Textual) — `ipv8lab tui`
- Packet fuzzer for protocol security testing — `ipv8lab fuzz`
- mTLS encryption layer for Zone Server auth — `ipv8lab mtls`
- ARP8-driven version selection per §2 — `ipv8lab arp8`
- Inter-Company Interop and Two-XLATE8 model per §4.6–4.7 — `ipv8lab interop`
- Private Interop ASN (65534/65533) reservation per §4.8
- Interior Link Convention (222.0.0.0/8) per §4.10 — `ipv8lab ilink`
- Address Usage Model per §4.11 — `ipv8lab usage`
- Socket API Compatibility mock (AF_INET8, sockaddr_in8) per §6.2 — `ipv8lab socket`
- CGNAT Behaviour simulation per §15 — `ipv8lab cgnat`
- XLATE8 Even/Odd Load Balancing per §15.1 — `ipv8lab xlate8lb`
- Cloud Provider VPC simulation per §17 — `ipv8lab vpc`
- RINE Prefix Protection per §19.3 — `ipv8lab rineprot`
- PyPI and Docker Hub publish workflows

### Changed
- Test count: 1160 → 1827

## [0.10.0] — 2026-05-14

### Added
- End-to-end integration scenario (DHCP8 → OAuth8 → ACL8 → routing)
- Multi-zone simulation with Zone Server pairs — `ipv8lab multizone`
- BGP8 path selection with CF metric — `ipv8lab bgp8`
- XLATE8 north-south traffic flow — `ipv8lab xlate8`
- Interactive Zone Server management CLI — `ipv8lab zone`
- CF performance dashboard with visualisation — `ipv8lab cf`
- PCAP export for Wireshark integration — `ipv8lab pcap`
- IPv8 packet fragmentation and reassembly — `ipv8lab frag`
- Traceroute8 diagnostic utility — `ipv8lab traceroute`

### Changed
- Test count: 680 → 988

## [0.9.0] — 2026-05-14

### Added
- Cost Factor (CF) metric simulation per §1.6
- WHOIS8 mock resolver (ASN validation, route validation)
- DHCP8 lease simulation per §1.3
- Zone Server mock (OAuth8 cache, ACL8 engine) per §1.3–1.4
- NetLog8 telemetry client (SEC-ALERT, E3 traps) per §18
- Companion spec modules: BGP8, IBGP8, OSPF8, IS-IS8, RINE, ARP8, XLATE8, Update8, WiFi8, SNMPv8

### Changed
- Test count: 498 → 680

## [0.8.0] — 2026-05-14

### Added
- Address class classification per §4
- Spec-compliant 28-byte packet header per §5.1
- Prefix validation and routing scope per §3.5, 3.9, 3.10
- Two-tier routing table per §8.7
- Multicast/broadcast classification per §10–12
- Border router ingress filtering per §18
- ICMPv8 protocol per §9
- 8to4 tunnelling per §13.3
- Device compliance tiers per §17.1–17.3
- NIC rate limits per §17.5
- DNS A8 record type per §7
- VRF per §8.8
- PVRST per §17.4

### Changed
- Test count: 320 → 498

## [0.7.0] — 2026-05-14

### Added
- Multi-hop mesh topologies with cycle detection
- Packet capture/replay (.iv8cap format) — `ipv8lab capture`
- Web UI dashboard (dark theme, JSON API) — `ipv8lab dashboard`
- Performance benchmarks (6 benchmarks) — `ipv8lab bench`
- Plugin system for custom protocols
- Error hierarchy (IPv8LabError)

### Changed
- Test count: 200 → 320

## [0.6.0] — 2026-05-14

### Added
- Packet hex dump utility — `ipv8lab packet dump`
- JSON output mode (`--json` flag) on all commands
- Mypy type checking in CI

## [0.5.0] — 2026-05-14

### Added
- UDP framing protocol (magic + length)
- Async UDP transport (send/receive)
- UDP node runner with forwarding — `ipv8lab udp run`
- UDP demo example

## [0.4.0] — 2026-05-14

### Added
- Node and Router abstractions for local testbed
- Two-ASN demo scenario
- Packet tracing through simulated networks

## [0.3.0] — 2026-05-14

### Added
- Route table and route lookup
- YAML config loader for network topologies
- Routing simulation — `ipv8lab route simulate`

## [0.2.0] — 2026-05-14

### Added
- IPv8 packet structure (28-byte header)
- Packet serialization and parsing
- CRC32 checksum
- CLI command — `ipv8lab packet`

## [0.1.0] — 2026-05-14

### Added
- IPv8Address class
- ASN ↔ prefix conversion
- Address validation
- CLI command — `ipv8lab addr`

[0.12.0]: https://github.com/LF3551/Open-IPv8-Lab/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/LF3551/Open-IPv8-Lab/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/LF3551/Open-IPv8-Lab/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/LF3551/Open-IPv8-Lab/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/LF3551/Open-IPv8-Lab/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/LF3551/Open-IPv8-Lab/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/LF3551/Open-IPv8-Lab/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/LF3551/Open-IPv8-Lab/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/LF3551/Open-IPv8-Lab/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/LF3551/Open-IPv8-Lab/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/LF3551/Open-IPv8-Lab/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/LF3551/Open-IPv8-Lab/releases/tag/v0.1.0
