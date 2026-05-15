[← Home](index.md)

# Spec Coverage

Complete mapping of [draft-thain-ipv8-02](https://www.ietf.org/archive/id/draft-thain-ipv8-02.html) sections to source modules.

## draft-thain-ipv8-02

| Section | Topic | Module | Tests |
|:-------:|-------|--------|:-----:|
| 1.3 | DHCP8 lease (single-response provisioning) | `dhcp8.py` | ✅ |
| 1.3 | Zone Server (OAuth8 cache, ACL8 engine) | `zoneserver.py` | ✅ |
| 1.4 | XLATE8 north-south traffic flow | `xlate8_flow.py` | ✅ |
| 1.6 | Cost Factor (CF) metric | `cost_factor.py` | ✅ |
| 2 | ARP8-driven version selection | `arp8_version.py` | ✅ |
| 3 | Address format (64-bit, ASN prefix + host) | `address.py` | ✅ |
| 4 | Address classes (unicast, multicast, broadcast, RINE, internal zone) | `address.py` | ✅ |
| 4.6–4.7 | Inter-Company Interop and Two-XLATE8 model | `interop.py` | ✅ |
| 4.10 | Interior Link Convention (222.0.0.0/8) | `interior_link.py` | ✅ |
| 4.11 | Address Usage Model — consolidated address space table | `addr_usage.py` | ✅ |
| 5.1 | Packet header (28-byte, version 8) | `packet.py` | ✅ |
| 5.1 | Packet fragmentation and reassembly (DF/MF, offset) | `fragmentation.py` | ✅ |
| 6 | ASN dot notation | `address.py` | ✅ |
| 6.2 | Socket API Compatibility (AF_INET8, sockaddr_in8) | `socket_api.py` | ✅ |
| 7 | DNS A8 record (even/odd pair, RFC 1918 validation) | `dns_a8.py` | ✅ |
| 8.4 | BGP8 path selection with CF metric | `bgp8_selection.py` | ✅ |
| 8.7 | Two-tier routing table | `route.py` | ✅ |
| 8.8 | VRF (management VLAN 4090, OOB VLAN 4091) | `vrf.py` | ✅ |
| 9 | ICMPv8 (Echo, Unreachable, Redirect, Time Exceeded) | `icmpv8.py` | ✅ |
| 10–12 | Multicast, anycast, broadcast | `multicast.py` | ✅ |
| 13.3 | 8to4 tunnelling | `tunnel.py` | ✅ |
| 15 | CGNAT Behaviour simulation | `cgnat.py` | ✅ |
| 15.1 | XLATE8 Even/Odd Load Balancing | `xlate8_lb.py` | ✅ |
| 17 | Cloud Provider VPC simulation | `cloud_vpc.py` | ✅ |
| 17.1–17.3 | Device compliance tiers | `compliance.py` | ✅ |
| 17.4 | PVRST (Zone Server root election) | `pvrst.py` | ✅ |
| 17.5 | NIC rate limits | `ratelimit.py` | ✅ |
| 18 | Security — ingress filtering, prefix protection | `security.py`, `validation.py` | ✅ |
| 18 | NetLog8 telemetry (SEC-ALERT, E3 traps) | `netlog8.py` | ✅ |
| 19.3 | RINE Prefix Protection (100.x.x.x filtering) | `rine_protection.py` | ✅ |
| 19.4 | Interior Link Convention Protection (222.0.0.0/8) | `ilink_protection.py` | ✅ |
| 19.7 | /16 Minimum Prefix Enforcement at eBGP8 | `prefix_enforce.py` | ✅ |

## Companion drafts

| Draft | Topic | Module | Tests |
|-------|-------|--------|:-----:|
| draft-thain-whois8-00 | Standalone WHOIS8 protocol | `whois8_proto.py` | ✅ |
| draft-thain-netlog8-00 | Standalone NetLog8 protocol | `netlog8_proto.py` | ✅ |
| draft-thain-routing-protocols-00 | BGP8, IBGP8, OSPF8, IS-IS8 | `companions.py` | ✅ |
| draft-thain-rine-00 | RINE peering fabric | `companions.py` | ✅ |
| draft-thain-support8-00 | ARP8 with gratuitous announce | `companions.py` | ✅ |
| draft-thain-zoneserver-00 | XLATE8 translation table | `companions.py` | ✅ |
| draft-thain-update8-00 | Update8 and NIC certification | `companions.py` | ✅ |
| draft-thain-wifi8-00 | WiFi8 protocol | `companions.py` | ✅ |
| draft-thain-ipv8-mib-00 | SNMPv8 MIB | `companions.py` | ✅ |

## Infrastructure modules

| Module | Purpose |
|--------|---------|
| `checksum.py` | CRC32 checksum utilities |
| `node.py` | Node abstraction for simulation |
| `simulator.py` | Network simulator (YAML config, mesh) |
| `transport.py` | UDP transport (async send/receive) |
| `udp_runner.py` | Async UDP node orchestration |
| `capture.py` | Packet capture/replay (.iv8cap) |
| `cf_dashboard.py` | CF performance dashboard (HTML, JSON API) |
| `dashboard.py` | Web dashboard (dark theme) |
| `benchmark.py` | Performance benchmarks |
| `plugin.py` | Plugin system |
| `errors.py` | Error hierarchy |
| `dump.py` | Hex dump & JSON output |
| `whois8.py` | WHOIS8 mock resolver |
| `integration.py` | End-to-end integration scenario |
| `multizone.py` | Multi-zone simulation |
| `nat8.py` | NAT8 address translation gateway |
| `netflow8.py` | NetFlow8 flow monitoring |
| `qos.py` | QoS / traffic shaping |
| `docker_testbed.py` | Docker-based testbed |
| `tui_dashboard.py` | TUI dashboard (Textual) |
| `fuzzer.py` | Packet fuzzer |
| `mtls.py` | mTLS encryption layer |
| `traceroute8.py` | Traceroute8 diagnostic |
| `pcap_export.py` | PCAP export for Wireshark |
