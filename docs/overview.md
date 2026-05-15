[← Home](index.md)

# Overview

Open-IPv8-Lab is an experimental userspace toolkit implementing [draft-thain-ipv8-02](https://www.ietf.org/archive/id/draft-thain-ipv8-02.html) — the Internet Protocol Version 8 specification.

## Why IPv8? — Comparison with IPv4 and IPv6

IPv8 is **not** a successor to IPv6. It is an independent experimental protocol described in draft-thain-ipv8-02, designed around a fundamentally different addressing and routing philosophy.

| | IPv4 | IPv6 | IPv8 |
|---|------|------|------|
| **Address size** | 32-bit | 128-bit | 64-bit |
| **Address format** | `a.b.c.d` | `xxxx:xxxx:…:xxxx` | `ASN.a.b.c.d` (ASN dot notation) |
| **Address structure** | Flat / CIDR prefix | Interface ID + prefix | **ASN routing prefix (32-bit) + host (32-bit)** |
| **Routing model** | BGP + IGP, flat RIB | Same as IPv4 | **Two-tier**: Tier 1 (inter-AS by ASN prefix) + Tier 2 (intra-AS by host) |
| **Path metric** | AS-path length, MED | Same as IPv4 | **Cost Factor (CF)** — 7 components: RTT, jitter, loss, bandwidth, hops, policy, Haversine physics floor |
| **NAT** | Widespread (NAT44) | Discouraged | **XLATE8** — structured north-south translation with DNS validation |
| **Service discovery** | DNS, mDNS | DNS, NDP, SLAAC | **Zone Server** — centralised OAuth8 + ACL8 + DHCP8 + DNS8 per AS |
| **Host config** | DHCP | SLAAC / DHCPv6 | **DHCP8** — single-response provisioning with all endpoints |
| **Security at border** | ACL, uRPF | ACL, IPsec | **Ingress filtering** + NIC rate limits + RINE prefix protection + mandatory compliance tiers |
| **Transition** | — | 6to4, NAT64, DS-Lite | **8to4 tunnelling** — IPv8 inside IPv4 for legacy transit |
| **Management** | SNMP, NetFlow | Same | **SNMPv8 MIB**, **NetLog8** (SEC-ALERT, E3 traps), **NetFlow8** |
| **Address exhaustion** | ~4.3 billion (exhausted) | ~3.4 × 10³⁸ | ~4.3 billion hosts per ASN × ~4.3 billion ASNs |
| **IETF status** | Standard (RFC 791) | Standard (RFC 8200) | **Experimental** (draft-thain-ipv8-02) |

### Key architectural differences

1. **ASN-centric addressing** — the network operator (ASN) is embedded directly in every address, eliminating the need for separate prefix allocation registries
2. **Mandatory Zone Server** — every AS has a centralised authority for authentication (OAuth8), access control (ACL8), and host configuration (DHCP8) — security is built into the architecture, not bolted on
3. **Cost Factor routing** — BGP8 uses a physics-aware 7-component metric instead of simple AS-path length, enabling quality-based path selection
4. **Structured NAT** — XLATE8 replaces ad-hoc NAT with a defined translation model including DNS validation and even/odd load balancing
5. **Companion protocol suite** — IPv8 ships with purpose-built replacements: ARP8, WHOIS8, NetLog8, WiFi8, Update8, rather than adapting IPv4-era protocols

> **Note:** IPv8 is an experimental protocol for research and education. IPv6 is the production successor to IPv4 and remains the IETF standard for next-generation Internet addressing.

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
- Traceroute8 diagnostic utility (`ipv8lab traceroute`)
- NAT8 address translation gateway simulation (`ipv8lab nat8`)
- NetFlow8 flow monitoring and telemetry export (`ipv8lab netflow8`)
- QoS / traffic shaping based on TOS field (`ipv8lab qos`)
- Docker-based multi-node testbed (`ipv8lab docker`)
- TUI dashboard — Rich Live / Textual (`ipv8lab tui`)
- Packet fuzzer for protocol security testing (`ipv8lab fuzz`)
- mTLS / encryption layer for Zone Server authentication (`ipv8lab mtls`)
- ARP8-driven version selection per Section 2 (`ipv8lab arp8`)
- Inter-Company Interop and Two-XLATE8 model per Sections 4.6–4.7 (`ipv8lab interop`)
- Interior Link Convention (222.0.0.0/8) per Section 4.10 (`ipv8lab ilink`)
- Address Usage Model — consolidated address space table per Section 4.11 (`ipv8lab usage`)
- Socket API Compatibility mock (AF_INET8, sockaddr_in8) per Section 6.2 (`ipv8lab socket`)
- CGNAT Behaviour simulation per Section 15 (`ipv8lab cgnat`)
- XLATE8 Even/Odd Load Balancing per Section 15.1 (`ipv8lab xlate8lb`)
- Cloud Provider VPC simulation per Section 17 (`ipv8lab vpc`)
- RINE Prefix Protection (100.x.x.x filtering) per Section 19.3 (`ipv8lab rineprot`)
- Interior Link Convention Protection (222.0.0.0/8 BGP8 filtering) per Section 19.4 (`ipv8lab ilinkprot`)
- /16 Minimum Prefix Enforcement at eBGP8 boundaries per Section 19.7 (`ipv8lab prefixenf`)
- Standalone WHOIS8 protocol (draft-thain-whois8-00): server, client with cache, record signing (`ipv8lab whois8`)
- Standalone NetLog8 protocol (draft-thain-netlog8-00): wire framing, collector, relay, rate limiting (`ipv8lab netlog8proto`)
- Mesh network simulation, packet capture/replay, web dashboard, benchmarks, plugin system

## What it does NOT do

- Does not modify the Linux kernel or network stack
- Does not require raw sockets or root access
- Is not production networking software
- Does not claim official IETF endorsement

## Design principles

1. **Spec-driven** — every module maps to a section in draft-thain-ipv8-02
2. **Userspace only** — everything runs as a normal user process
3. **Tested** — 1827 tests covering all implemented sections
4. **Extensible** — plugin system for custom protocol experiments
5. **Safe** — no system modifications, no privilege escalation
