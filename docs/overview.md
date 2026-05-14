# Overview

Open-IPv8-Lab is an experimental userspace toolkit implementing [draft-thain-ipv8-00](https://www.ietf.org/archive/id/draft-thain-ipv8-00.html) — the Internet Protocol Version 8 specification.

## What it does

- Parses and validates IPv8 64-bit addresses (ASN dot notation and full 8-octet format)
- Classifies addresses: unicast, multicast, broadcast, RINE, internal zone, interop (Section 4)
- Converts ASN values to 4-octet routing prefixes and back (Section 3.4)
- Builds and parses spec-compliant 28-byte IPv8 packets (Section 5.1)
- Two-tier routing: Tier 1 (ASN prefix) + Tier 2 (host n.n.n.n) (Section 8.7)
- Virtual Routing and Forwarding with mandatory management/OOB VRFs (Section 8.8)
- ICMPv8: Echo Request/Reply, Destination Unreachable, Time Exceeded, Redirect (Section 9)
- Multicast classification with well-known group names (Sections 10–12)
- 8to4 tunnelling: IPv8 packet encapsulation for IPv4-only transit (Section 13.3)
- DNS A8 records with even/odd pair convention and RFC 1918 validation (Section 7)
- Device compliance tier checking: Tier 1/2/3 (Sections 17.1–17.3)
- PVRST spanning tree with Zone Server root election (Section 17.4)
- NIC firmware rate limiting: broadcast, unauthenticated, authenticated (Section 17.5)
- Border router ingress filtering: ASN spoofing, prefix protection (Section 18)
- Cost Factor (CF) metric: 7-component path quality with Haversine physics floor (Section 1.6)
- WHOIS8 mock resolver: ASN registration, route/destination validation
- DHCP8 lease simulation: single-response provisioning with all service endpoints (Section 1.3)
- Zone Server mock: OAuth8 JWT cache, ACL8 east-west access control (Sections 1.3, 1.4)
- NetLog8 telemetry client: structured logging with SEC-ALERT and E3 traps (Section 18)
- Companion spec modules: BGP8, OSPF8, IS-IS8, RINE, ARP8, XLATE8, Update8, WiFi8, SNMPv8
- End-to-end integration scenario: DHCP8 → OAuth8 → ACL8 → routing in one lifecycle
- Multi-zone simulation: Zone Server pairs with IBGP8-style inter-zone routing
- BGP8 path selection with CF metric: per-prefix RIB, anomaly detection, failover
- XLATE8 north-south traffic flow: DNS8 → XLATE8 → translation → ingress (Section 1.4)
- PCAP export for Wireshark integration: PcapWriter, PcapReader, Lua dissector (DLT_USER0)
- IPv8 packet fragmentation and reassembly: DF/MF flags, fragment offset, stateful Reassembler
- Interactive CLI for Zone Server management (`ipv8lab zone`)
- Mesh network simulation, packet capture/replay, web dashboard, benchmarks, plugin system

## What it does NOT do

- Does not modify the Linux kernel or network stack
- Does not require raw sockets or root access
- Is not production networking software
- Does not claim official IETF endorsement

## Design principles

1. **Spec-driven** — every module maps to a section in draft-thain-ipv8-00
2. **Userspace only** — everything runs as a normal user process
3. **Tested** — 1220 tests covering all implemented sections
4. **Extensible** — plugin system for custom protocol experiments
5. **Safe** — no system modifications, no privilege escalation
