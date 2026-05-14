# Testbed & Transport

## Two-ASN demo

The default demo creates two autonomous systems:

```
ASN 64496
  node-a: 64496.192.0.2.1
  router-a

ASN 64497
  node-b: 64497.198.51.100.7
  router-b
```

### Scenario

1. `node-a` sends a packet to `node-b`
2. `router-a` reads the destination prefix (Tier 1 lookup)
3. `router-a` forwards to `router-b`
4. `router-b` delivers the packet to `node-b` (Tier 2 lookup)
5. `node-b` receives the payload

### Running the demo

```bash
ipv8lab route simulate --config examples/two_asn_demo.yaml
```

## Three-ASN mesh demo

```bash
ipv8lab route simulate --config examples/three_asn_mesh.yaml
```

## UDP transport

Nodes run as separate async processes communicating over UDP:

```bash
ipv8lab udp run --config examples/udp_demo.py
```

UDP framing uses `IV8L` magic header + 4-byte length prefix.

## Packet capture

Capture packets to `.iv8cap` files for replay:

```bash
ipv8lab capture start --output trace.iv8cap
ipv8lab capture replay --input trace.iv8cap
```

## Web dashboard

Minimal web UI for topology visualization and packet sending:

```bash
ipv8lab dashboard --port 8080
```

JSON API: `/api/topology`, `/api/send`

## 8to4 tunnelling (Section 13.3)

IPv8 packets can be encapsulated in `8TO4` frames for transit across IPv4-only networks. The tunnel frame uses a 4-byte magic (`8TO4`), flags byte, and payload length.

## DHCP8 lease simulation (Section 1.3)

A device connecting to an IPv8 network sends one DHCP8 Discover and receives one response containing every service endpoint it requires:

- IPv8 address assignment from a pool
- Default gateways (even/odd pair per Section 17.1)
- Zone Server endpoints (primary .254, secondary .253)
- DNS8, NTP8, NetLog8, OAuth8 cache endpoints
- Management VRF (VLAN 4090), OOB VRF (VLAN 4091)

## Zone Server (Section 1.3)

Paired active/active platform at .254 (primary) and .253 (secondary):

- **OAuth8 cache** — local JWT validation without round-trips to external identity providers
- **ACL8 engine** — east-west access control enforcement, default deny, three enforcement layers
- **Service registry** — DHCP8, DNS8, NTP8, NetLog8, OAuth8, WHOIS8, ACL8, XLATE8

## NetLog8 telemetry (Section 18)

Unified telemetry format with structured entries:

- 8 severity levels (EMERGENCY → DEBUG)
- 14 facility codes (ROUTING, SECURITY, DHCP8, OAUTH8, etc.)
- SEC-ALERT events for security violations
- E3 traps for interior link convention violations

## Companion specs

Stub modules for all companion specifications:

- **BGP8/IBGP8/OSPF8/IS-IS8** — routing protocol data structures (draft-thain-routing-protocols-00)
- **RINE** — peering fabric (draft-thain-rine-00)
- **ARP8** — cache table with gratuitous announce (draft-thain-support8-00)
- **XLATE8** — DNS-validated translation table (draft-thain-zoneserver-00)
- **Update8** — firmware updates from DNS-named sources only (draft-thain-update8-00)
- **WiFi8** — access points with Zone Server integration (draft-thain-wifi8-00)
- **SNMPv8** — MIB tree (draft-thain-ipv8-mib-00)
