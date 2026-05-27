[← Home](index.md)

# Architecture


## An RN is a Fancy VRF (Section 3.2)

A **Routing Number (RN)** is not merely an address prefix — it is a full
Virtual Routing & Forwarding (VRF) context.  Every interface binding creates a
VRF named `ipv8-asn-<RN>` with Route Distinguisher `<RN>:65535`.

Key rules:
- A router keeps a **local VRF only for RNs it originates or terminates**.
  Transit RNs live in the RIB (`route.py`) but have no forwarding context.
- A segment has **exactly one Primary RN**.  All IPv4-addressed devices on the
  segment share that Primary RN as their RN context.
- A device MAY hold **Secondary RN addresses** in other RNs (multi-homing).

> **Important:** The union-on-`iphdr` model (treating RN as a pure prefix
> overlay on the IP header) is **not** the implementation model.  RNs are
> VRF identifiers that drive forwarding table selection.

## Design Principles

1. **Spec-driven** — every module maps to a section in draft-thain-ipv8 or a companion draft
2. **Userspace only** — everything runs as a normal user process, no kernel modifications
3. **Tested** — 2100+ tests covering all modules
4. **Extensible** — plugin system for custom protocol experiments
5. **CLI-first** — every feature is accessible via `ipv8lab` CLI with `--json` support

## Project Layout

```
Open-IPv8-Lab/
├── src/ipv8lab/           # Main package
│   ├── cli/               # Typer CLI commands (35 subcommands)
│   ├── address.py         # Core: addressing (Sections 3, 4, 6)
│   ├── packet.py          # Core: packet format (Section 5.1)
│   ├── route.py           # Core: routing (Section 8.7)
│   └── ...                # 58 modules total
├── tests/                 # pytest test suite (1827 tests)
├── docs/                  # Documentation
├── examples/              # YAML configs and demo scripts
└── pyproject.toml         # Build config
```

## Module Categories

### Core Protocol Stack

These modules implement the fundamental IPv8 protocol:

```
address.py ──→ packet.py ──→ route.py ──→ icmpv8.py
    │              │             │
    ▼              ▼             ▼
checksum.py   fragmentation.py  vrf.py
```

- **address.py** — 64-bit IPv8 address parsing, encoding, classification
- **packet.py** — 28-byte header: `!BBHHHBBHIIII` (version 8)
- **checksum.py** — CRC32 per spec
- **route.py** — Two-tier routing: Tier 1 (ASN prefix) → Tier 2 (host)
- **vrf.py** — Virtual Routing & Forwarding: management (VLAN 4090), OOB (4091)
- **icmpv8.py** — Echo, Unreachable, Redirect, Time Exceeded
- **fragmentation.py** — DF/MF flags, stateful Reassembler
- **tunnel.py** — 8to4 tunnelling for IPv4-only transit

### Address Space

- **addr_usage.py** — Address Usage Model table (Section 4.11)
- **multicast.py** — Multicast/anycast/broadcast classification (Sections 10–12)
- **interior_link.py** — Interior Link Convention, 222.0.0.0/8 (Section 4.10)
- **interop.py** — Inter-Company Interop prefix 127.127.0.0, Two-XLATE8 (Sections 4.6–4.7)

### Zone Server & Services

```
zoneserver.py ──→ dhcp8.py
     │
     ├──→ mtls.py (TLS layer)
     └──→ integration.py (end-to-end lifecycle)
```

- **zoneserver.py** — OAuth8 JWT cache, ACL8 engine, service registry
- **dhcp8.py** — Single-response lease provisioning
- **mtls.py** — mTLS certificate management, handshake simulation
- **multizone.py** — Multi-zone simulation with Zone Server pairs
- **dns_a8.py** — DNS A8 records with even/odd pair convention

### Routing & BGP8

```
bgp8_selection.py ──→ cost_factor.py
       │
       ▼
 cf_dashboard.py
```

- **bgp8_selection.py** — Per-prefix RIB, anomaly detection, failover
- **cost_factor.py** — 7-component CF metric with Haversine physics floor
- **cf_dashboard.py** — HTML dashboard for CF visualization
- **arp8_version.py** — ARP8-driven version selection

### Translation & NAT

- **xlate8.py** — Unified XLATE8 subsystem: 5 modes (native/4-to-8/8-to-4/NAPT-RN/encap), north-south flow, even/odd LB
- **cgnat.py** — CGNAT: RN preservation, LA-only NAT (Section 15)
- **nat8.py** — NAT8 gateway: static, dynamic, PAT

### Security & Compliance

```
security.py ──→ validation.py
     │
     ├──→ rine_protection.py   (100.x.x.x)
     ├──→ ilink_protection.py  (222.0.0.0/8)
     └──→ prefix_enforce.py    (/16 minimum)
```

- **security.py** — Border router ingress filtering
- **validation.py** — Prefix validation rules
- **rine_protection.py** — RINE Prefix Protection with SEC-ALERT
- **ilink_protection.py** — Interior Link Convention Protection with E3 traps
- **prefix_enforce.py** — /16 minimum at eBGP8 boundaries
- **compliance.py** — Device compliance tiers 1/2/3
- **pvrst.py** — Per-VLAN Rapid Spanning Tree
- **ratelimit.py** — NIC firmware rate limits

### Companion Protocols

- **whois8_proto.py** — Standalone WHOIS8 (draft-thain-whois8): server, client, HMAC signing, RIR hierarchy
- **netlog8_proto.py** — Standalone NetLog8 (draft-thain-netlog8): wire framing, collector, relay, rate limiter
- **whois8.py** — WHOIS8 mock resolver
- **netlog8.py** — NetLog8 telemetry client (SEC-ALERT, E3 traps)
- **companions.py** — BGP8, OSPF8, IS-IS8, RINE, ARP8, XLATE8, Update8, WiFi8, SNMPv8

### Operations & Tooling

- **netflow8.py** — Flow monitoring, telemetry export
- **qos.py** — Traffic classification and shaping (PQ, WFQ, Token Bucket)
- **traceroute8.py** — Multi-hop traceroute diagnostic
- **pcap_export.py** — PCAP export: PcapWriter, PcapReader, Lua dissector
- **fuzzer.py** — Packet fuzzer for security testing
- **docker_testbed.py** — Docker multi-node testbed generator
- **cloud_vpc.py** — Cloud Provider VPC simulation

### Simulation Infrastructure

- **simulator.py** — YAML config loader, mesh topologies, cycle detection
- **node.py** — Node abstraction
- **transport.py** — Async UDP transport
- **udp_runner.py** — UDP node orchestration
- **capture.py** — Packet capture/replay (.iv8cap format)
- **dashboard.py** — Web dashboard (dark theme, JSON API)
- **tui_dashboard.py** — TUI dashboard (Rich / Textual)
- **benchmark.py** — Performance benchmarks (6 benchmarks)
- **plugin.py** — Plugin system for custom protocols
- **socket_api.py** — AF_INET8 socket mock

### Shared Utilities

- **errors.py** — Exception hierarchy (IPv8LabError)
- **dump.py** — Hex dump & JSON output

## CLI Architecture

The CLI is built with [Typer](https://typer.tiangolo.com/) and follows a consistent pattern:

```
src/ipv8lab/cli/
├── main.py          # Root app with 35 subcommands
├── addr.py          # ipv8lab addr
├── packet_cli.py    # ipv8lab packet
├── route_cli.py     # ipv8lab route
└── ...              # One file per subcommand
```

Every CLI module:
- Uses `typer.Typer(no_args_is_help=True)`
- Supports `--json` flag for JSON output
- Uses `typer.echo()` for output
- Is testable via `typer.testing.CliRunner`
