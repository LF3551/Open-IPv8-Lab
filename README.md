# Open-IPv8-Lab

<p align="center">
  <img src="https://raw.githubusercontent.com/LF3551/Open-IPv8-Lab/main/assets/logo.png" alt="Open-IPv8-Lab" width="100%">
</p>

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![SPDX](https://img.shields.io/badge/SPDX-Apache--2.0-brightgreen.svg)](https://spdx.org/licenses/Apache-2.0.html)
[![Tests](https://github.com/LF3551/Open-IPv8-Lab/actions/workflows/tests.yml/badge.svg)](https://github.com/LF3551/Open-IPv8-Lab/actions/workflows/tests.yml)

Experimental userspace toolkit implementing [draft-thain-ipv8-02](https://www.ietf.org/archive/id/draft-thain-ipv8-02.html) — the Internet Protocol Version 8 specification. **58 modules**, **35 CLI commands**, **1827 tests**.

> **Educational project.** Not an official IPv8 implementation, not production networking software.

Created and maintained by **Aleksei Aleinikov** ([@LF3551](https://github.com/LF3551)).

---

## Quick Start

```bash
# Install
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Parse an IPv8 address
ipv8lab addr parse 64496.192.0.2.1

# Build a packet
ipv8lab packet build --src 64496.192.0.2.1 --dst 64497.198.51.100.7 --payload "hello"

# Routing simulation
ipv8lab route simulate --config examples/two_asn_demo.yaml

# Zone Server lifecycle
ipv8lab zone init --prefix 127.1.0.0
ipv8lab zone oauth-issue device-42

# Security filtering
ipv8lab ilinkprot bgp8 --prefix 222.0.0.0 --origin 64496
ipv8lab prefixenf check --prefix 0.0.251.240 --length 24 --origin 64496

# WHOIS8 registry
ipv8lab whois8 register --asn 64496 --holder "Example Corp" --rir ARIN
ipv8lab whois8 lookup --asn 64496

# Export to Wireshark
ipv8lab pcap demo -o demo.pcap
ipv8lab pcap dissector -o ipv8_dissector.lua

# JSON output on any command
ipv8lab addr parse 64496.192.0.2.1 --json
```

➜ **[More examples](docs/examples.md)** — 10 step-by-step walkthroughs

---

## Features

### Core Protocol Stack

| Feature | CLI | Spec |
|---------|-----|:----:|
| IPv8 64-bit addressing (ASN prefix + host) | `ipv8lab addr` | §3, 4, 6 |
| 28-byte packet header | `ipv8lab packet` | §5.1 |
| Packet fragmentation / reassembly | `ipv8lab frag` | §5.1 |
| Two-tier routing with VRF | `ipv8lab route` | §8.7, 8.8 |
| ICMPv8 (Echo, Unreachable, Redirect) | — | §9 |
| Multicast / anycast / broadcast | — | §10–12 |
| 8to4 tunnelling | — | §13.3 |
| DNS A8 records (even/odd pair) | — | §7 |

### Zone Server & Services

| Feature | CLI | Spec |
|---------|-----|:----:|
| Zone Server (OAuth8, ACL8, DHCP8) | `ipv8lab zone` | §1.3, 1.4 |
| Multi-zone simulation | `ipv8lab multizone` | — |
| mTLS encryption layer | `ipv8lab mtls` | — |
| Cloud Provider VPC mapping | `ipv8lab vpc` | §17 |

### Routing & Traffic

| Feature | CLI | Spec |
|---------|-----|:----:|
| BGP8 path selection with CF metric | `ipv8lab bgp8` | §8.4 |
| Cost Factor (7-component metric) | `ipv8lab cf` | §1.6 |
| XLATE8 north-south traffic flow | `ipv8lab xlate8` | §1.4 |
| XLATE8 Even/Odd Load Balancing | `ipv8lab xlate8lb` | §15.1 |
| NAT8 address translation | `ipv8lab nat8` | — |
| CGNAT Behaviour simulation | `ipv8lab cgnat` | §15 |
| ARP8-driven version selection | `ipv8lab arp8` | §2 |
| Inter-Company Interop | `ipv8lab interop` | §4.6–4.7 |

### Security & Compliance

| Feature | CLI | Spec |
|---------|-----|:----:|
| RINE Prefix Protection (100.x.x.x) | `ipv8lab rineprot` | §19.3 |
| Interior Link Protection (222.0.0.0/8) | `ipv8lab ilinkprot` | §19.4 |
| /16 Minimum Prefix Enforcement | `ipv8lab prefixenf` | §19.7 |
| Border router ingress filtering | — | §18 |
| Device compliance tiers | — | §17.1–17.3 |
| PVRST spanning tree | — | §17.4 |
| NIC rate limits | — | §17.5 |

### Companion Protocols

| Feature | CLI | Draft |
|---------|-----|-------|
| WHOIS8 protocol (server, client, HMAC signing) | `ipv8lab whois8` | whois8-00 |
| NetLog8 protocol (wire framing, collector, relay) | `ipv8lab netlog8proto` | netlog8-00 |
| BGP8, OSPF8, IS-IS8, RINE, ARP8, XLATE8, WiFi8, SNMPv8 | — | 7 companion drafts |

### Operations & Tooling

| Feature | CLI |
|---------|-----|
| PCAP export for Wireshark | `ipv8lab pcap` |
| Traceroute8 diagnostic | `ipv8lab traceroute` |
| NetFlow8 flow monitoring | `ipv8lab netflow8` |
| QoS / traffic shaping | `ipv8lab qos` |
| Packet fuzzer | `ipv8lab fuzz` |
| Docker multi-node testbed | `ipv8lab docker` |
| TUI dashboard (Textual) | `ipv8lab tui` |
| Web dashboard | `ipv8lab dashboard` |
| Performance benchmarks | `ipv8lab bench` |
| Packet capture / replay | `ipv8lab capture` |
| Socket API mock (AF_INET8) | `ipv8lab socket` |
| Address Usage Model table | `ipv8lab usage` |
| Interior Link Convention | `ipv8lab ilink` |

---

## Example Output

```
$ ipv8lab addr parse 64496.192.0.2.1

Input                64496.192.0.2.1
Format               ASN dot notation
ASN                  64496
Routing prefix       0.0.251.240
Host part            192.0.2.1
Full notation        0.0.251.240.192.0.2.1
```

---

## Testing

```bash
pytest -v
```

1827 tests covering all 58 modules.

---

## Documentation

| Doc | Description |
|-----|-------------|
| **[Examples](docs/examples.md)** | 10 step-by-step walkthroughs |
| **[CLI Reference](docs/cli-reference.md)** | All 35 commands with usage examples |
| **[Spec Coverage](docs/spec-coverage.md)** | Full draft-thain-ipv8-02 mapping |
| **[Architecture](docs/architecture.md)** | Module categories & dependencies |
| [Overview](docs/overview.md) | Project overview |
| [Addressing](docs/addressing.md) | IPv8 address format (Sections 3, 4, 6) |
| [Packet Format](docs/packet-format.md) | 28-byte header (Section 5.1) |
| [Routing Simulator](docs/routing-simulator.md) | Two-tier routing (Sections 8.7, 8.8) |
| [Testbed](docs/testbed.md) | Local testbed setup |
| [Roadmap](docs/roadmap.md) | Version history & future plans |

---

## License

[Apache License 2.0](LICENSE) · SPDX: `Apache-2.0`

## Attribution

```
IPv8 Lab — Copyright 2026 Aleksei Aleinikov
https://github.com/LF3551/Open-IPv8-Lab
```

Use, modification, and distribution are permitted under the Apache License 2.0,
provided that the original copyright notice and the [NOTICE](NOTICE) file are preserved.
Attribution to **Aleksei Aleinikov** ([@LF3551](https://github.com/LF3551)) must remain intact.
