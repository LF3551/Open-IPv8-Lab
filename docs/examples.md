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
$ ipv8lab usage show
```

---

## 2. Building & Inspecting Packets

28-byte IPv8 packet header per Section 5.1.

```bash
# Build a packet with payload
$ ipv8lab packet build --src 64496.192.0.2.1 --dst 64497.198.51.100.7 --payload "hello"

# Hex dump of a packet
$ ipv8lab packet dump --src 64496.10.0.0.1 --dst 64497.10.0.0.2 --payload "test"

# Fragment a large packet (MTU = 64 bytes)
$ ipv8lab frag fragment --src 64496.10.0.0.1 --dst 64497.10.0.0.2 --size 256 --mtu 64

# Packet fuzzer — test header robustness
$ ipv8lab fuzz run --iterations 100 --json
```

---

## 3. Routing Simulation

Two-tier routing: Tier 1 (ASN prefix) → Tier 2 (host n.n.n.n).

```bash
# Simulate with YAML config
$ ipv8lab route simulate --config examples/two_asn_demo.yaml

# Traceroute diagnostic
$ ipv8lab traceroute trace --dst 64497.10.0.0.1 --hops 8 --json
```

### Cost Factor metric

7-component path quality score (Section 1.6).

```bash
# Compute CF for a path
$ ipv8lab cf compute --latency 12.5 --bandwidth 1000 --jitter 0.3
```

---

## 4. Zone Server Lifecycle

Zone Server provides OAuth8, ACL8, DHCP8, service registry per Sections 1.3–1.4.

```bash
# Step 1: Initialize Zone Server for a zone prefix
$ ipv8lab zone init --prefix 127.1.0.0

# Step 2: Issue an OAuth8 JWT token for a device
$ ipv8lab zone oauth-issue device-42

# Step 3: Add an ACL8 rule
$ ipv8lab zone acl-add "*" gateway --action permit

# Step 4: Check VLAN compliance
$ ipv8lab zone vlan-check 100

# Step 5: List registered services
$ ipv8lab zone services

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
$ ipv8lab multizone init --zones 3
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
# Initialize BGP8 router
$ ipv8lab bgp8 init --asn 64496

# Advertise a prefix
$ ipv8lab bgp8 advertise --prefix 0.0.251.240 --next-hop 0.0.251.241

# View RIB
$ ipv8lab bgp8 rib

# Best-path selection
$ ipv8lab bgp8 best-path --prefix 0.0.251.240 --json
```

### XLATE8 traffic flow

```bash
# North-south translation
$ ipv8lab xlate8 init
$ ipv8lab xlate8 translate --src 64496.10.0.0.1
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
$ ipv8lab rineprot bgp8 --prefix 100.0.0.0
$ ipv8lab rineprot traps --json
```

### Interior Link Protection (Section 19.4)

```bash
$ ipv8lab ilinkprot init
$ ipv8lab ilinkprot bgp8 --prefix 222.0.0.0 --origin 64496
$ ipv8lab ilinkprot packet --src 222.0.0.1.10.0.0.1 --dst 64496.10.0.0.1
$ ipv8lab ilinkprot traps --json
```

### /16 Minimum Prefix Enforcement (Section 19.7)

```bash
$ ipv8lab prefixenf init
$ ipv8lab prefixenf check --prefix 0.0.251.240 --length 24 --origin 64496
$ ipv8lab prefixenf alerts --json
```

### CGNAT Behaviour (Section 15)

```bash
$ ipv8lab cgnat init
$ ipv8lab cgnat translate --src 10.0.0.1
$ ipv8lab cgnat status --json
```

---

## 8. WHOIS8 Registry

Standalone WHOIS8 protocol per draft-thain-whois8-00.

```bash
# Initialize server
$ ipv8lab whois8 init

# Register an ASN
$ ipv8lab whois8 register --asn 64496 --holder "Example Corp" --rir ARIN

# Register a route object
$ ipv8lab whois8 route --asn 64496 --prefix 0.0.251.240 --length 16

# Lookup
$ ipv8lab whois8 lookup --asn 64496

# Validate route authorization
$ ipv8lab whois8 validate --asn 64496 --prefix 0.0.251.240

# Anycast lookup
$ ipv8lab whois8 anycast --prefix 0.0.251.240

# Verify HMAC-SHA256 signature
$ ipv8lab whois8 verify --asn 64496

# List all records
$ ipv8lab whois8 list --json
```

---

## 9. NetLog8 Monitoring

Standalone NetLog8 protocol per draft-thain-netlog8-00.

```bash
# Initialize collector
$ ipv8lab netlog8proto init

# Log a message (severity 6 = Informational, facility 1)
$ ipv8lab netlog8proto log --severity 6 --facility 1 --message "link up"

# Security alert
$ ipv8lab netlog8proto sec-alert --message "spoofed prefix detected" --source 64496

# E3 trap
$ ipv8lab netlog8proto e3-trap --message "interior link leak" --source 222.0.0.1

# Query by severity
$ ipv8lab netlog8proto query --severity 4

# Add alert rule
$ ipv8lab netlog8proto add-rule --name critical --severity-min 2

# Export
$ ipv8lab netlog8proto export --format jsonl

# Wire header info
$ ipv8lab netlog8proto header-info
```

---

## 10. End-to-End Integration

Full lifecycle: DHCP8 → OAuth8 → ACL8 → routing → telemetry.

```bash
# Run the built-in integration scenario
$ ipv8lab zone init --prefix 127.1.0.0
$ ipv8lab zone oauth-issue device-42
$ ipv8lab zone acl-add device-42 gateway --action permit
$ ipv8lab route simulate --config examples/two_asn_demo.yaml
$ ipv8lab netlog8proto log --severity 6 --facility 1 --message "integration test"
$ ipv8lab whois8 register --asn 64496 --holder "Lab Corp" --rir ARIN
$ ipv8lab whois8 validate --asn 64496 --prefix 0.0.251.240
```

### NAT8 & NetFlow8

```bash
# NAT8 gateway
$ ipv8lab nat8 init --mode dynamic
$ ipv8lab nat8 add --inside 10.0.0.1 --outside 64496.10.0.0.1
$ ipv8lab nat8 table

# NetFlow8 monitoring
$ ipv8lab netflow8 init
$ ipv8lab netflow8 flows
$ ipv8lab netflow8 export --format jsonl
```

### QoS & Docker Testbed

```bash
# QoS classification
$ ipv8lab qos init
$ ipv8lab qos classify --tos 46
$ ipv8lab qos queues

# Docker testbed
$ ipv8lab docker generate --nodes 4 --topology mesh
$ ipv8lab docker status --json
```

---

## Tips

- **JSON everywhere**: Add `--json` to any command for machine-readable output
- **Benchmarks**: `ipv8lab bench run --json` for all 6 benchmarks
- **TUI**: `ipv8lab tui launch` for a live terminal dashboard
- **Web dashboard**: `ipv8lab dashboard serve --port 8080`
- **Packet capture**: `ipv8lab capture start -o trace.iv8cap` then `ipv8lab pcap export trace.iv8cap out.pcap`
