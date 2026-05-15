# Examples

Step-by-step walkthroughs for common IPv8 Lab scenarios.

## Table of Contents

- [1. Address Parsing & Validation](#1-address-parsing--validation)
- [2. Building & Inspecting Packets](#2-building--inspecting-packets)
- [3. Routing Simulation](#3-routing-simulation)
- [4. Zone Server Lifecycle](#4-zone-server-lifecycle)
- [5. PCAP Export & Wireshark](#5-pcap-export--wireshark)
- [6. BGP8 Path Selection](#6-bgp8-path-selection)
- [7. Security Filtering](#7-security-filtering)
- [8. WHOIS8 Registry](#8-whois8-registry)
- [9. NetLog8 Monitoring](#9-netlog8-monitoring)
- [10. End-to-End Integration](#10-end-to-end-integration)

---

## 1. Address Parsing & Validation

IPv8 addresses are 64 bits: a 32-bit ASN routing prefix + a 32-bit host part.

```bash
# ASN dot notation → full 8-octet notation
$ ipv8lab addr parse 64496.192.0.2.1
Input                64496.192.0.2.1
Format               ASN dot notation
ASN                  64496
Routing prefix       0.0.251.240
Host part            192.0.2.1
Full notation        0.0.251.240.192.0.2.1

# Full 8-octet → ASN
$ ipv8lab addr parse 0.0.251.240.192.0.2.1
Input                0.0.251.240.192.0.2.1
Format               Full 8-octet
ASN                  64496
Routing prefix       0.0.251.240
Host part            192.0.2.1
Full notation        0.0.251.240.192.0.2.1

# Encode ASN to routing prefix
$ ipv8lab addr encode-asn 64496
0.0.251.240

# Decode prefix back
$ ipv8lab addr decode-prefix 0.0.251.240
64496

# Classify address type
$ ipv8lab addr classify 64496.192.0.2.1
Type: unicast

# Classify multicast
$ ipv8lab addr classify 64496.224.0.0.1
Type: multicast

# Classify RINE
$ ipv8lab addr classify 64496.100.0.0.1
Type: rine_prefix

# JSON output (all commands)
$ ipv8lab addr parse 64496.192.0.2.1 --json
{"input": "64496.192.0.2.1", "format": "asn_dot", "asn": 64496, ...}
```

### Address Usage Model

```bash
# Show the full address space allocation table (Section 4.11)
$ ipv8lab usage table
```

---

## 2. Building & Inspecting Packets

28-byte IPv8 packet header per Section 5.1.

```bash
# Build a packet with payload
$ ipv8lab packet build --src 64496.192.0.2.1 --dst 64497.198.51.100.7 --payload "hello"

# Hex dump of a binary packet file
$ ipv8lab packet dump packet.bin

# Fragment a large packet (MTU = 64 bytes)
$ ipv8lab frag fragment --src 64496.10.0.0.1 --dst 64497.10.0.0.2 --size 256 --mtu 64

# Packet fuzzer — test header robustness
$ ipv8lab fuzz run --count 100 --json
```

---

## 3. Routing Simulation

Two-tier routing: Tier 1 (ASN prefix) → Tier 2 (host n.n.n.n).

```bash
# Simulate with YAML config
$ ipv8lab route simulate --config examples/two_asn_demo.yaml

# Traceroute diagnostic
$ ipv8lab traceroute run 64496.10.0.0.1 64497.10.0.0.1 --hops 8 --json
```

### Cost Factor metric

7-component path quality score (Section 1.6).

```bash
# Run demo with 4 paths (includes anomaly detection)
$ ipv8lab cf demo --json
```

---

## 4. Zone Server Lifecycle

Zone Server provides OAuth8, ACL8, DHCP8, service registry per Sections 1.3–1.4.

```bash
# Step 1: Initialize Zone Server for a zone prefix
$ ipv8lab zone init --prefix 127.1.0.0

# Step 2: Add an ACL8 rule
$ ipv8lab zone acl-add "*" gateway --action permit

# Step 3: Check VLAN compliance
$ ipv8lab zone vlan-check 100

# Step 4: List registered services
$ ipv8lab zone service-list

# Full status
$ ipv8lab zone status --json
```

### mTLS encryption

```bash
# Initialize CA
$ ipv8lab mtls init

# Issue and handshake
$ ipv8lab mtls issue my-device
$ ipv8lab mtls handshake my-device

# Encrypt a message
$ ipv8lab mtls encrypt my-device "secret payload"
```

### Multi-zone simulation

```bash
# Initialize 3 zones with Zone Server pairs
$ ipv8lab multizone init
$ ipv8lab multizone status --json
```

---

## 5. PCAP Export & Wireshark

Export IPv8 packets to standard PCAP format for Wireshark.

```bash
# Generate a demo PCAP file
$ ipv8lab pcap demo -o demo.pcap

# Inspect it
$ ipv8lab pcap inspect demo.pcap

# Generate Wireshark Lua dissector
$ ipv8lab pcap dissector -o ipv8_dissector.lua

# Export .iv8cap capture to .pcap
$ ipv8lab pcap export trace.iv8cap trace.pcap
```

Load `ipv8_dissector.lua` in Wireshark: **Help → About → Folders → Personal Lua Plugins**.

---

## 6. BGP8 Path Selection

Per-prefix RIB with CF metric, anomaly detection, failover.

```bash
# BGP8 path selection (positional: PREFIX ORIGIN_ASN)
$ ipv8lab bgp8 init --asn 64496
$ ipv8lab bgp8 advertise 64496.0.0.0.0/8 64496 --next-hop 0.0.251.241
$ ipv8lab bgp8 rib
$ ipv8lab bgp8 select 64496.0.0.0.0/8 --json
```

### XLATE8 traffic flow

```bash
# North-south translation
$ ipv8lab xlate8 init
$ ipv8lab xlate8 demo --json
$ ipv8lab xlate8 table

# Even/Odd Load Balancing (Section 15.1)
$ ipv8lab xlate8lb init
$ ipv8lab xlate8lb status --json
```

---

## 7. Security Filtering

### RINE Prefix Protection (Section 19.3)

```bash
$ ipv8lab rineprot init
$ ipv8lab rineprot bgp8 64496.100.0.0.1
$ ipv8lab rineprot alerts --json
```

### Interior Link Protection (Section 19.4)

```bash
$ ipv8lab ilinkprot init
$ ipv8lab ilinkprot bgp8 64496.222.0.0.1
$ ipv8lab ilinkprot packet 64496.222.0.0.1
$ ipv8lab ilinkprot traps --json
```

### /16 Minimum Prefix Enforcement (Section 19.7)

```bash
$ ipv8lab prefixenf init
$ ipv8lab prefixenf check 64496.10.1.0.0 24 --peer-asn 64497
$ ipv8lab prefixenf alerts --json
```

### CGNAT Behaviour (Section 15)

```bash
$ ipv8lab cgnat init
$ ipv8lab cgnat translate 64496.10.0.0.1
$ ipv8lab cgnat status --json
```

---

## 8. WHOIS8 Registry

Standalone WHOIS8 protocol per draft-thain-whois8-00.

```bash
# Initialize server
$ ipv8lab whois8 init

# Register an ASN (positional: ASN HOLDER)
$ ipv8lab whois8 register 64496 "Example Corp" --rir ARIN

# Register a route object (positional: ASN PREFIX_LENGTH)
$ ipv8lab whois8 route 64496 16

# Lookup (positional: ASN)
$ ipv8lab whois8 lookup 64496

# Validate route authorization (positional: ASN [PREFIX_LENGTH])
$ ipv8lab whois8 validate 64496 16

# Anycast lookup (positional: ASN)
$ ipv8lab whois8 anycast 64496

# Verify HMAC-SHA256 signature (positional: ASN)
$ ipv8lab whois8 verify 64496

# List all records
$ ipv8lab whois8 list --json
```

---

## 9. NetLog8 Monitoring

Standalone NetLog8 protocol per draft-thain-netlog8-00.

```bash
# Initialize collector
$ ipv8lab netlog8proto init

# Log a message (positional: MESSAGE, severity/facility as text)
$ ipv8lab netlog8proto log "link up" --severity INFO --facility GENERAL

# Security alert (positional: MESSAGE)
$ ipv8lab netlog8proto sec-alert "spoofed prefix detected"

# E3 trap (positional: MESSAGE)
$ ipv8lab netlog8proto e3-trap "interior link leak"

# Query by severity
$ ipv8lab netlog8proto query --severity ALERT

# Add alert rule (positional: NAME)
$ ipv8lab netlog8proto add-rule critical --severity ALERT

# Export
$ ipv8lab netlog8proto export --fmt jsonl

# Wire header info
$ ipv8lab netlog8proto header-info
```

---

## 10. End-to-End Integration

Full lifecycle: DHCP8 → OAuth8 → ACL8 → routing → telemetry.

```bash
# Run the built-in integration scenario
$ ipv8lab zone init --prefix 127.1.0.0
$ ipv8lab zone acl-add device-42 gateway --action permit
$ ipv8lab route simulate --config examples/two_asn_demo.yaml
$ ipv8lab netlog8proto log "integration test" --severity INFO --facility GENERAL
$ ipv8lab whois8 register 64496 "Lab Corp" --rir ARIN
$ ipv8lab whois8 validate 64496 16
```

### NAT8 & NetFlow8

```bash
# NAT8 gateway
$ ipv8lab nat8 demo --json

# NetFlow8 monitoring
$ ipv8lab netflow8 demo --json
```

### QoS & Docker Testbed

```bash
# QoS classification
$ ipv8lab qos demo

# Docker testbed
$ ipv8lab docker demo --json
```

---

## Tips

- **JSON everywhere**: Add `--json` to any command for machine-readable output
- **Benchmarks**: `ipv8lab bench run --json` for all 6 benchmarks
- **TUI**: `ipv8lab tui run` for a live terminal dashboard
- **Web dashboard**: `ipv8lab dashboard serve examples/two_asn_demo.yaml --port 8080`
- **Packet capture**: `ipv8lab capture info trace.iv8cap` then `ipv8lab pcap export trace.iv8cap out.pcap`
