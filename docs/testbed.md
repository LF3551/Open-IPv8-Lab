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
ipv8lab udp run --config examples/two_asn_demo.yaml
```

UDP framing uses `IV8L` magic header + 4-byte length prefix.

## Packet capture

Capture packets to `.iv8cap` files for replay:

```bash
ipv8lab capture read trace.iv8cap
ipv8lab capture info trace.iv8cap
```

## Web dashboard

Minimal web UI for topology visualization and packet sending:

```bash
ipv8lab dashboard serve examples/two_asn_demo.yaml --port 8080
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

## Integration scenarios (v0.10)

### End-to-end integration

Full device onboarding lifecycle in 7 steps:

1. Zone Server pair setup (primary .254, secondary .253)
2. DHCP8 device provisioning (single-response)
3. OAuth8 authentication (JWT issue + validate)
4. ACL8 authorisation (east-west enforcement)
5. WHOIS8 egress validation (north-south)
6. Packet routing (two-tier table)
7. Ingress filter (ASN spoofing detection)

### Multi-zone simulation

Multiple internal zones (127.x.0.0) with full service stacks connected via IBGP8-style inter-zone routing:

- Zone isolation via ACL8 default deny
- Bidirectional Tier 1 routes between zones
- Device provisioning and authentication per zone

### BGP8 path selection with CF metric

Per-prefix RIB with CF-based best path selection:

- Lowest accumulated CF wins
- AS-path length and origin ASN tie-breaks
- CF anomaly detection (RTT vs physics floor)
- AS-path loop rejection, /16 minimum prefix validation
- Withdraw + automatic failover

### XLATE8 north-south traffic flow (Section 1.4)

DNS8 → XLATE8 state table → address translation:

- **Egress**: internal 127.x → external ASN address rewrite
- **Ingress**: reverse XLATE8 lookup → internal address rewrite
- No DNS lookup = no XLATE8 entry = blocked
- Full round-trip simulation

### Zone Server CLI (`ipv8lab zone`)

Interactive management of Zone Server pairs:

```bash
# Initialize a zone
ipv8lab zone init --prefix 127.1.0.0

# Show status
ipv8lab zone status --json

# Manage services
ipv8lab zone service-add DHCP8 dhcp.127.1.0.0
ipv8lab zone service-list

# ACL8 rules
ipv8lab zone acl-add "*" gateway --action permit
ipv8lab zone acl-check dev-01 gateway

# OAuth8 tokens
ipv8lab zone oauth-issue device-42
ipv8lab zone oauth-validate <token>

# PVRST VLAN check
ipv8lab zone vlan-check 100
```

### PCAP export for Wireshark (`ipv8lab pcap`)

Export IPv8 packet captures to standard PCAP format for analysis in Wireshark:

```bash
# Generate a demo .pcap with sample packets
ipv8lab pcap demo -o demo.pcap

# Convert .iv8cap capture to .pcap
ipv8lab pcap export trace.iv8cap trace.pcap

# Inspect a .pcap file
ipv8lab pcap inspect demo.pcap

# Write packets directly to .pcap
ipv8lab pcap write test.pcap --src 64496.10.0.1.1 --dst 64497.10.0.1.100 -n 10

# Generate Wireshark Lua dissector
ipv8lab pcap dissector -o ipv8_dissector.lua
```

The PCAP files use classic libpcap format with DLT_USER0 (147) link type.
The Lua dissector auto-registers with `wtap_encap` for seamless Wireshark integration.
