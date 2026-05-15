[← Back to README](../README.md)

# Glossary

Key terms and abbreviations used in Open-IPv8-Lab and [draft-thain-ipv8-02](https://www.ietf.org/archive/id/draft-thain-ipv8-02.html).

## Addressing

| Term | Definition |
|------|-----------|
| **IPv8** | Internet Protocol Version 8 — experimental 64-bit addressing protocol defined in draft-thain-ipv8-02 |
| **ASN** | Autonomous System Number — 32-bit routing prefix identifying a network operator (upper half of an IPv8 address) |
| **Host part** | Lower 32 bits of an IPv8 address, analogous to host portion in IPv4 |
| **ASN dot notation** | Human-readable format: `ASN.a.b.c.d` (e.g. `64496.192.0.2.1`) |
| **Full notation** | 8-octet format: `p1.p2.p3.p4.h1.h2.h3.h4` (e.g. `0.0.251.240.192.0.2.1`) |
| **Routing prefix** | 4-octet representation of ASN used in routing tables |
| **Address class** | Classification per §4: unicast, multicast, broadcast, RINE, internal zone, interop |

## Routing & Transport

| Term | Definition |
|------|-----------|
| **Two-tier routing** | Routing architecture per §8.7 — Tier 1 routes by ASN prefix between AS domains, Tier 2 routes by host address within an AS |
| **VRF** | Virtual Routing and Forwarding per §8.8 — isolated routing instances; mandatory management (VLAN 4090) and OOB (VLAN 4091) VRFs |
| **BGP8** | Border Gateway Protocol for IPv8 — inter-AS path-vector routing with CF metric (§8.4) |
| **IBGP8** | Internal BGP8 — iBGP variant for intra-AS route distribution |
| **OSPF8** | Open Shortest Path First for IPv8 — link-state intra-AS routing |
| **IS-IS8** | Intermediate System to Intermediate System for IPv8 — alternative link-state IGP |
| **CF** | Cost Factor — 7-component path quality metric (RTT, jitter, loss, bandwidth, hops, policy, Haversine physics floor) per §1.6 |
| **ICMPv8** | Internet Control Message Protocol for IPv8 — Echo, Destination Unreachable, Redirect, Time Exceeded (§9) |
| **8to4 tunnel** | Encapsulation of IPv8 packets inside IPv4 for transit over legacy networks (§13.3) |

## Zone Server & Services

| Term | Definition |
|------|-----------|
| **Zone Server** | Centralised authority per §1.3–1.4 — provides DHCP8, OAuth8, ACL8, DNS8, and service discovery within an AS |
| **OAuth8** | Authentication and authorisation service — issues JWT tokens for inter-zone and intra-zone access |
| **ACL8** | Access Control List engine — east-west traffic policy enforcement (§1.4) |
| **DHCP8** | Dynamic Host Configuration Protocol for IPv8 — single-response lease provisioning with all service endpoints (§1.3) |
| **DNS A8** | DNS record type for IPv8 addresses — even/odd pair convention with RFC 1918 validation (§7) |

## Address Translation

| Term | Definition |
|------|-----------|
| **XLATE8** | Translation table — north-south NAT with DNS validation for traffic between IPv8 zones (§1.4) |
| **XLATE8 LB** | Even/Odd Load Balancing — splits traffic across two XLATE8 instances (§15.1) |
| **NAT8** | Network Address Translation for IPv8 — static, dynamic, and PAT modes |
| **CGNAT** | Carrier-Grade NAT per §15 — `r.r.r.r` preservation, `n.n.n.n`-only NAT rules |

## Peering & Interop

| Term | Definition |
|------|-----------|
| **RINE** | Regional Internet Network Exchange — peering fabric between ASNs (draft-thain-rine-00) |
| **Interop prefix** | `127.127.0.0` — Inter-Company Interop address and Two-XLATE8 model (§4.6–4.7) |
| **Private Interop ASN** | ASN 65534/65533 — reserved for private peering (§4.8) |
| **Interior Link** | `222.0.0.0/8` — convention address range for point-to-point links (§4.10) |

## Security & Compliance

| Term | Definition |
|------|-----------|
| **Ingress filtering** | Border router checks: reject spoofed ASN prefixes, enforce source validation (§18) |
| **RINE Prefix Protection** | Filtering of `100.x.x.x` addresses at RINE boundaries with SEC-ALERT (§19.3) |
| **Interior Link Protection** | BGP8 filtering of `222.0.0.0/8` prefixes — prevents leaking internal links (§19.4) |
| **Prefix Enforcement** | /16 minimum prefix length at eBGP8 boundaries — blocks overly specific routes (§19.7) |
| **Compliance tier** | Device certification levels: Tier 1 (basic), Tier 2 (full), Tier 3 (carrier-grade) per §17.1–17.3 |
| **PVRST** | Per-VLAN Rapid Spanning Tree — Zone Server elected as root (§17.4) |
| **NIC rate limit** | Firmware-level rate limiting: broadcast, unauthenticated, authenticated packets (§17.5) |
| **mTLS** | Mutual TLS — encryption layer for Zone Server authentication |

## Companion Protocols

| Term | Definition |
|------|-----------|
| **WHOIS8** | Registry protocol — ASN registration, route validation, HMAC record signing (draft-thain-whois8-00) |
| **NetLog8** | Telemetry protocol — structured logging with SEC-ALERT and E3 traps, wire framing, collector, relay (draft-thain-netlog8-00) |
| **ARP8** | Address Resolution Protocol for IPv8 — gratuitous announce, version selection (§2, draft-thain-support8-00) |
| **Update8** | Firmware/software update protocol with NIC certification (draft-thain-update8-00) |
| **WiFi8** | Wireless protocol adaptation for IPv8 (draft-thain-wifi8-00) |
| **SNMPv8** | Simple Network Management Protocol for IPv8 — MIB definitions (draft-thain-ipv8-mib-00) |
| **NetFlow8** | Flow monitoring and telemetry export in `.nf8` binary format |

## Operations & Tooling

| Term | Definition |
|------|-----------|
| **TUI** | Terminal User Interface — Rich Live / Textual dashboard for real-time monitoring |
| **PCAP** | Packet Capture format — `.pcap` export with DLT_USER0 for Wireshark analysis |
| **iv8cap** | Open-IPv8-Lab native capture format for packet capture/replay |
| **Packet fuzzer** | Security testing tool — generates malformed packets to test protocol robustness |
| **VPC** | Virtual Private Cloud — cloud provider zone prefix → VPC mapping (§17) |
| **AF_INET8** | Socket address family constant for IPv8 socket API compatibility (§6.2) |
