# Open-IPv8-Lab

<p align="center">
  <img src="assets/logo.png" alt="Open-IPv8-Lab" width="100%">
</p>

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![SPDX](https://img.shields.io/badge/SPDX-Apache--2.0-brightgreen.svg)](https://spdx.org/licenses/Apache-2.0.html)
[![Tests](https://github.com/LF3551/Open-IPv8-Lab/actions/workflows/tests.yml/badge.svg)](https://github.com/LF3551/Open-IPv8-Lab/actions/workflows/tests.yml)

Open-IPv8-Lab is an experimental userspace toolkit implementing [draft-thain-ipv8-00](https://www.ietf.org/archive/id/draft-thain-ipv8-00.html) — the Internet Protocol Version 8 specification. It covers ASN-based 64-bit addressing, packet encoding/decoding, two-tier routing, ICMPv8, 8to4 tunnelling, security filtering, VRF, PVRST, and more.

Created and maintained by Aleksei Aleinikov ([@LF3551](https://github.com/LF3551)).

## Status

> **This project is experimental and educational.** It is not an official IPv8 implementation, not production networking software.

## Spec coverage (draft-thain-ipv8-00)

| Section | Topic | Module |
|---------|-------|--------|
| 3 | Address format (64-bit, ASN prefix + host) | `address.py` |
| 4 | Address classes (unicast, multicast, broadcast, RINE, internal zone) | `address.py` |
| 5.1 | Packet header (28-byte, version 8) | `packet.py` |
| 6 | ASN dot notation | `address.py` |
| 7 | DNS A8 record (even/odd pair, RFC 1918 validation) | `dns_a8.py` |
| 8.7 | Two-tier routing table | `route.py` |
| 8.8 | VRF (management VLAN 4090, OOB VLAN 4091) | `vrf.py` |
| 9 | ICMPv8 (Echo, Unreachable, Redirect, Time Exceeded) | `icmpv8.py` |
| 10–12 | Multicast, anycast, broadcast | `multicast.py` |
| 13.3 | 8to4 tunnelling | `tunnel.py` |
| 17.1–17.3 | Device compliance tiers | `compliance.py` |
| 17.4 | PVRST (Zone Server root election) | `pvrst.py` |
| 17.5 | NIC rate limits | `ratelimit.py` |
| 18 | Security — ingress filtering, prefix protection | `security.py`, `validation.py` |

## Goals

- Parse and validate IPv8 64-bit addresses (Section 3)
- Classify address types: unicast, multicast, broadcast, RINE, internal zone (Section 4)
- Build and parse spec-compliant IPv8 packets (Section 5.1)
- Two-tier routing simulation with VRF support (Sections 8.7, 8.8)
- ICMPv8 messages: Echo, Destination Unreachable, Redirect (Section 9)
- 8to4 tunnelling for IPv8-over-IPv4 transit (Section 13.3)
- DNS A8 record parsing with even/odd pair convention (Section 7)
- Device compliance tier validation (Sections 17.1–17.3)
- PVRST Zone Server root election (Section 17.4)
- NIC firmware rate limiting simulation (Section 17.5)
- Border router ingress filtering and security checks (Section 18)
- Mesh network simulation, packet capture, web dashboard, benchmarks, plugins

## Non-goals

- No Linux kernel modifications
- No production networking
- No real BGP integration
- No claim of official IETF endorsement

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Quick start

```bash
# Parse an IPv8 address
ipv8lab addr parse 64496.192.0.2.1

# Convert ASN to routing prefix
ipv8lab addr encode-asn 64496

# Decode prefix back to ASN
ipv8lab addr decode-prefix 0.0.251.240

# Build a packet
ipv8lab packet build --src 64496.192.0.2.1 --dst 64497.198.51.100.7 --payload "hello"

# Parse a packet from file
ipv8lab packet parse packet.bin

# Run routing simulation
ipv8lab route simulate --config examples/two_asn_demo.yaml
```

## Example output

```
ipv8lab addr parse 64496.192.0.2.1

Input                64496.192.0.2.1
Format               ASN dot notation
ASN                  64496
Routing prefix       0.0.251.240
Host part            192.0.2.1
Full notation        0.0.251.240.192.0.2.1
```

## Testing

```bash
pytest -v
```

311 tests covering all implemented spec sections.

## Project structure

```
src/ipv8lab/
├── address.py        # IPv8 64-bit addressing (Section 3, 4, 6)
├── packet.py         # Packet header (Section 5.1)
├── checksum.py       # CRC32 checksum
├── route.py          # Two-tier routing (Section 8.7)
├── vrf.py            # Virtual Routing & Forwarding (Section 8.8)
├── icmpv8.py         # ICMPv8 protocol (Section 9)
├── multicast.py      # Multicast/broadcast (Sections 10–12)
├── tunnel.py         # 8to4 tunnelling (Section 13.3)
├── dns_a8.py         # DNS A8 records (Section 7)
├── compliance.py     # Device compliance tiers (Sections 17.1–17.3)
├── pvrst.py          # PVRST spanning tree (Section 17.4)
├── ratelimit.py      # NIC rate limits (Section 17.5)
├── security.py       # Ingress filtering (Section 18)
├── validation.py     # Prefix validation (Sections 3.5, 3.9, 3.10)
├── errors.py         # Error hierarchy
├── node.py           # Node abstraction
├── simulator.py      # Mesh network simulator
├── transport.py      # UDP transport
├── udp_runner.py     # Async UDP node orchestration
├── capture.py        # Packet capture (.iv8cap)
├── dashboard.py      # Web dashboard
├── benchmark.py      # Performance benchmarks
├── plugin.py         # Plugin system
├── dump.py           # Hex dump & JSON output
└── cli/              # Typer CLI commands
```

## Documentation

- [Overview](docs/overview.md)
- [Addressing](docs/addressing.md)
- [Packet format](docs/packet-format.md)
- [Routing simulator](docs/routing-simulator.md)
- [Testbed](docs/testbed.md)
- [Roadmap](docs/roadmap.md)

## License

This project is licensed under the [Apache License 2.0](LICENSE).

SPDX-License-Identifier: `Apache-2.0`

## Attribution

Use, modification, and distribution are permitted under the Apache License 2.0,
provided that the following conditions are met:

- The original copyright notice and license text must be preserved in all copies or substantial portions of the software.
- The [NOTICE](NOTICE) file must be included in any redistribution.
- Attribution to the original author — **Aleksei Aleinikov** ([@LF3551](https://github.com/LF3551)) — must remain intact.

If you use this project in your own work, please credit:

```
IPv8 Lab — Copyright 2026 Aleksei Aleinikov
https://github.com/LF3551/Open-IPv8-Lab
```
