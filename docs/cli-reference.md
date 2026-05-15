[← Home](index.md)

# CLI Reference

All commands support `--json` for machine-readable output.

## Table of Contents

| Command | Description | Spec Section |
|---------|-------------|:------------:|
| [`ipv8lab addr`](#addr) | IPv8 address operations | 3, 4, 6 |
| [`ipv8lab packet`](#packet) | Packet build / parse / dump | 5.1 |
| [`ipv8lab route`](#route) | Routing simulation | 8.7, 8.8 |
| [`ipv8lab zone`](#zone) | Zone Server management | 1.3, 1.4 |
| [`ipv8lab multizone`](#multizone) | Multi-zone simulation | — |
| [`ipv8lab bgp8`](#bgp8) | BGP8 path selection with CF | 8.4 |
| [`ipv8lab xlate8`](#xlate8) | XLATE8 north-south traffic flow | 1.4 |
| [`ipv8lab xlate8lb`](#xlate8lb) | XLATE8 Even/Odd Load Balancing | 15.1 |
| [`ipv8lab pcap`](#pcap) | PCAP export for Wireshark | — |
| [`ipv8lab frag`](#frag) | Packet fragmentation / reassembly | 5.1 |
| [`ipv8lab traceroute`](#traceroute) | Traceroute8 diagnostic | — |
| [`ipv8lab nat8`](#nat8) | NAT8 address translation | — |
| [`ipv8lab netflow8`](#netflow8) | NetFlow8 flow monitoring | — |
| [`ipv8lab qos`](#qos) | QoS / traffic shaping | — |
| [`ipv8lab cf`](#cf) | CF performance dashboard | 1.6 |
| [`ipv8lab fuzz`](#fuzz) | Packet fuzzer | — |
| [`ipv8lab mtls`](#mtls) | mTLS encryption layer | — |
| [`ipv8lab docker`](#docker) | Docker multi-node testbed | — |
| [`ipv8lab tui`](#tui) | TUI dashboard | — |
| [`ipv8lab bench`](#bench) | Performance benchmarks | — |
| [`ipv8lab capture`](#capture) | Packet capture / replay | — |
| [`ipv8lab dashboard`](#dashboard) | Web UI dashboard | — |
| [`ipv8lab udp`](#udp) | UDP transport experiments | — |
| [`ipv8lab usage`](#usage) | Address Usage Model table | 4.11 |
| [`ipv8lab arp8`](#arp8) | ARP8 version selection | 2 |
| [`ipv8lab interop`](#interop) | Inter-Company Interop | 4.6–4.7 |
| [`ipv8lab ilink`](#ilink) | Interior Link Convention | 4.10 |
| [`ipv8lab socket`](#socket) | Socket API Compatibility | 6.2 |
| [`ipv8lab cgnat`](#cgnat) | CGNAT Behaviour simulation | 15 |
| [`ipv8lab vpc`](#vpc) | Cloud Provider VPC mapping | 17 |
| [`ipv8lab rineprot`](#rineprot) | RINE Prefix Protection | 19.3 |
| [`ipv8lab ilinkprot`](#ilinkprot) | Interior Link Protection | 19.4 |
| [`ipv8lab prefixenf`](#prefixenf) | /16 Minimum Prefix Enforcement | 19.7 |
| [`ipv8lab whois8`](#whois8) | Standalone WHOIS8 protocol | whois8-00 |
| [`ipv8lab netlog8proto`](#netlog8proto) | Standalone NetLog8 protocol | netlog8-00 |

---

## addr

Parse, validate, and convert IPv8 addresses.

```bash
# Parse an address (ASN dot notation)
ipv8lab addr parse 64496.192.0.2.1

# Parse full 8-octet notation
ipv8lab addr parse 0.0.251.240.192.0.2.1

# Encode ASN to routing prefix
ipv8lab addr encode-asn 64496

# Decode prefix back to ASN
ipv8lab addr decode-prefix 0.0.251.240

# Classify address type
ipv8lab addr classify 64496.192.0.2.1

# Validate address
ipv8lab addr validate 64496.192.0.2.1

# JSON output
ipv8lab addr parse 64496.192.0.2.1 --json
```

## packet

Build, parse, and inspect IPv8 packets.

```bash
# Build a packet
ipv8lab packet build --src 64496.192.0.2.1 --dst 64497.198.51.100.7 --payload "hello"

# Parse a packet from binary file
ipv8lab packet parse packet.bin

# Hex dump of a binary packet file
ipv8lab packet dump packet.bin
```

## route

Two-tier routing simulation.

```bash
# Simulate routing with YAML config
ipv8lab route simulate --config examples/two_asn_demo.yaml
```

## zone

Zone Server management: OAuth8, ACL8, VLAN, services.

```bash
# Initialize Zone Server
ipv8lab zone init --prefix 127.1.0.0

# Show status
ipv8lab zone status

# Add ACL rule
ipv8lab zone acl-add "*" gateway --action permit

# Validate VLAN
ipv8lab zone vlan-check 100

# List services
ipv8lab zone service-list
```

## multizone

Multi-zone simulation with Zone Server pairs.

```bash
# Initialize multi-zone topology
ipv8lab multizone init

# Show topology status
ipv8lab multizone status
```

## bgp8

BGP8 path selection with Cost Factor metric.

```bash
# Initialize BGP8 router
ipv8lab bgp8 init --asn 64496

# Advertise prefix (positional: PREFIX ORIGIN_ASN)
ipv8lab bgp8 advertise 64496.0.0.0.0/8 64496 --next-hop 0.0.251.241

# Show RIB
ipv8lab bgp8 rib

# Path selection (positional: PREFIX)
ipv8lab bgp8 select 64496.0.0.0.0/8

# Run demo
ipv8lab bgp8 demo --json
```

## xlate8

XLATE8 north-south traffic flow.

```bash
# Initialize XLATE8 gateway
ipv8lab xlate8 init

# Egress flow: DNS8 → XLATE8 → translate
ipv8lab xlate8 demo --json

# Show translation table
ipv8lab xlate8 table
```

## xlate8lb

XLATE8 Even/Odd Load Balancing per Section 15.1.

```bash
# Initialize load balancer
ipv8lab xlate8lb init

# Show balancing status
ipv8lab xlate8lb status --json
```

## pcap

PCAP export for Wireshark integration.

```bash
# Generate demo PCAP file
ipv8lab pcap demo -o demo.pcap

# Inspect existing PCAP
ipv8lab pcap inspect demo.pcap

# Generate Wireshark Lua dissector
ipv8lab pcap dissector -o ipv8_dissector.lua

# Export .iv8cap to .pcap
ipv8lab pcap export trace.iv8cap trace.pcap
```

## frag

IPv8 packet fragmentation and reassembly.

```bash
# Fragment a large payload (all options)
ipv8lab frag fragment --src 64496.10.0.1.1 --dst 64497.10.0.1.100 --size 256 --mtu 64

# Fragment & reassemble round-trip
ipv8lab frag reassemble --size 3000 --mtu 1500 --json

# Show fragmentation info
ipv8lab frag info --json

# Run demo
ipv8lab frag demo
```

## traceroute

Traceroute8 diagnostic utility.

```bash
# Trace route (positional: SRC DST)
ipv8lab traceroute run 64496.10.0.0.1 64497.10.0.0.1 --hops 5

# Diamond topology demo
ipv8lab traceroute diamond --json

# Run all demo topologies
ipv8lab traceroute demo
```

## nat8

NAT8 address translation gateway.

```bash
# Initialize NAT8 gateway
ipv8lab nat8 init --mode dynamic

# Add static mapping (positional: INTERNAL EXTERNAL)
ipv8lab nat8 add-static 10.0.0.1 64496.10.0.0.1

# Translate a packet
ipv8lab nat8 translate --src 10.0.0.1 --dst 64497.10.0.0.1

# Show mappings
ipv8lab nat8 mappings

# Status
ipv8lab nat8 status --json

# Run demo
ipv8lab nat8 demo
```

## netflow8

NetFlow8 flow monitoring and telemetry.

```bash
# Start monitoring
ipv8lab netflow8 init

# Show top flows
ipv8lab netflow8 top

# Export flows
ipv8lab netflow8 export --all --json

# Export to .nf8 binary
ipv8lab netflow8 export -o flows.nf8

# Show protocols
ipv8lab netflow8 protocols

# Status
ipv8lab netflow8 status --json

# Run demo
ipv8lab netflow8 demo
```

## qos

QoS traffic shaping based on TOS field.

```bash
# Initialize QoS engine
ipv8lab qos init

# Classify packet
ipv8lab qos classify --src 64496.10.0.0.1 --dst 64497.10.0.0.2 --tos 46

# Show queues
ipv8lab qos queues

# Status
ipv8lab qos status --json

# Run demo
ipv8lab qos demo
```

## cf

CF (Cost Factor) performance dashboard.

```bash
# Run demo with 4 paths
ipv8lab cf demo --json

# Status
ipv8lab cf status --json
```

## fuzz

Packet fuzzer for protocol security testing.

```bash
# Run fuzzer (1000 iterations)
ipv8lab fuzz run --count 1000

# All strategies
ipv8lab fuzz run --strategy combined --json

# List strategies
ipv8lab fuzz strategies
```

## mtls

mTLS encryption layer for Zone Server authentication.

```bash
# Initialize CA
ipv8lab mtls init

# Issue device certificate
ipv8lab mtls issue my-device

# TLS handshake simulation
ipv8lab mtls handshake my-device

# Encrypt message (positional: DEVICE MESSAGE)
ipv8lab mtls encrypt my-device "secret payload"
```

## docker

Docker-based multi-node testbed.

```bash
# Run demo testbed
ipv8lab docker demo --json

# Show status
ipv8lab docker status --json
```

## tui

TUI dashboard powered by Rich Live / Textual.

```bash
# Launch TUI
ipv8lab tui run

# Demo data
ipv8lab tui demo --json
```

## bench

Performance benchmarks.

```bash
# Run all benchmarks
ipv8lab bench run

# JSON output
ipv8lab bench run --json
```

## capture

Packet capture and replay (.iv8cap format).

```bash
# Read packets from a capture file
ipv8lab capture read trace.iv8cap

# Show capture file info
ipv8lab capture info trace.iv8cap
```

## dashboard

Web UI dashboard (dark theme, JSON API).

```bash
# Launch web dashboard
ipv8lab dashboard serve examples/two_asn_demo.yaml --port 8080
```

## udp

UDP transport experiments.

```bash
# Run UDP transport demo
ipv8lab udp run --config examples/two_asn_demo.yaml
```

## usage

Address Usage Model table per Section 4.11.

```bash
# Show full address space table
ipv8lab usage table

# JSON output
ipv8lab usage table --json

# Classify an address
ipv8lab usage classify 64496.192.0.2.1
```

## arp8

ARP8-driven version selection per Section 2.

```bash
# Discover neighbour (positional: TARGET)
ipv8lab arp8 discover 64496.10.0.0.1

# Show version selection (positional: SRC DST)
ipv8lab arp8 select 64496.10.0.0.1 64497.10.0.0.2

# Show ARP8 cache
ipv8lab arp8 cache --json

# Status
ipv8lab arp8 status --json
```

## interop

Inter-Company Interop and Two-XLATE8 model (Sections 4.6–4.7).

```bash
# Initialize interop
ipv8lab interop init

# Show interop status
ipv8lab interop status --json

# Run demo
ipv8lab interop demo --json
```

## ilink

Interior Link Convention (222.0.0.0/8) per Section 4.10.

```bash
# Generate interior link /31 pairs
ipv8lab ilink generate 64496

# Validate address
ipv8lab ilink validate 64496.222.0.0.1

# Summary
ipv8lab ilink summary 64496 --json
```

## socket

Socket API Compatibility mock (AF_INET8) per Section 6.2.

```bash
# Show AF_INET8 info
ipv8lab socket info --json

# Create sockaddr_in8 (positional: ADDRESS)
ipv8lab socket create 64496.10.0.0.1 --json

# Status
ipv8lab socket status --json
```

## cgnat

CGNAT Behaviour simulation per Section 15.

```bash
# Initialize CGNAT
ipv8lab cgnat init

# Translate (positional: ADDRESS)
ipv8lab cgnat translate 64496.10.0.0.1

# Validate translation preserved r.r.r.r (positional: ORIGINAL TRANSLATED)
ipv8lab cgnat validate 64496.10.0.0.1 64496.10.0.0.1

# Show bindings
ipv8lab cgnat bindings

# Status
ipv8lab cgnat status --json
```

## vpc

Cloud Provider VPC simulation per Section 17.

```bash
# Initialize VPC
ipv8lab vpc init --asn 64496

# Show VPC list
ipv8lab vpc list --json

# Status
ipv8lab vpc status --json
```

## rineprot

RINE Prefix Protection per Section 19.3.

```bash
# Initialize RINE protection
ipv8lab rineprot init

# Check BGP8 advertisement (positional: PREFIX)
ipv8lab rineprot bgp8 64496.100.0.0.1

# Check packet (positional: ADDRESS)
ipv8lab rineprot check 64496.100.0.0.1

# Show alerts
ipv8lab rineprot alerts --json

# Status
ipv8lab rineprot status --json
```

## ilinkprot

Interior Link Convention Protection per Section 19.4.

```bash
# Initialize filter
ipv8lab ilinkprot init

# Check BGP8 advertisement (positional: PREFIX)
ipv8lab ilinkprot bgp8 64496.222.0.0.1

# Check egress packet (positional: ADDRESS)
ipv8lab ilinkprot packet 64496.222.0.0.1

# Show traps
ipv8lab ilinkprot traps --json

# Status
ipv8lab ilinkprot status --json
```

## prefixenf

/16 Minimum Prefix Enforcement at eBGP8 boundaries per Section 19.7.

```bash
# Initialize enforcer
ipv8lab prefixenf init

# Check advertisement (positional: PREFIX LENGTH)
ipv8lab prefixenf check 64496.10.1.0.0 24 --peer-asn 64497

# Show alerts
ipv8lab prefixenf alerts --json

# Status
ipv8lab prefixenf status --json
```

## whois8

Standalone WHOIS8 protocol (draft-thain-whois8-00).

```bash
# Initialize WHOIS8 server
ipv8lab whois8 init

# Register ASN (positional: ASN HOLDER)
ipv8lab whois8 register 64496 "Example Corp" --rir ARIN

# Register route (positional: ASN PREFIX_LENGTH)
ipv8lab whois8 route 64496 16

# Lookup ASN (positional: ASN)
ipv8lab whois8 lookup 64496

# Validate route (positional: ASN [PREFIX_LENGTH])
ipv8lab whois8 validate 64496 16

# Anycast lookup (positional: ASN)
ipv8lab whois8 anycast 64496

# Verify record signature (positional: ASN)
ipv8lab whois8 verify 64496

# List all records
ipv8lab whois8 list

# Show cache
ipv8lab whois8 cache --json

# Status
ipv8lab whois8 status --json
```

## netlog8proto

Standalone NetLog8 protocol (draft-thain-netlog8-00).

```bash
# Initialize collector
ipv8lab netlog8proto init

# Log message (positional: MESSAGE)
ipv8lab netlog8proto log "link up" --severity INFO --facility GENERAL

# Security alert (positional: MESSAGE)
ipv8lab netlog8proto sec-alert "spoofed prefix detected"

# E3 trap (positional: MESSAGE)
ipv8lab netlog8proto e3-trap "interior link leak"

# Query logs
ipv8lab netlog8proto query --severity ALERT --event-type SEC_ALERT

# Add alert rule (positional: NAME)
ipv8lab netlog8proto add-rule critical --severity ALERT

# Show alerts
ipv8lab netlog8proto alerts --json

# Export logs
ipv8lab netlog8proto export --fmt jsonl

# Show header info
ipv8lab netlog8proto header-info

# Status
ipv8lab netlog8proto status --json
```
