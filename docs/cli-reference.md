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

# Hex dump
ipv8lab packet dump --src 64496.10.0.0.1 --dst 64497.10.0.0.2 --payload "test"
```

## route

Two-tier routing simulation.

```bash
# Simulate routing with YAML config
ipv8lab route simulate --config examples/two_asn_demo.yaml

# Add a route
ipv8lab route add --prefix 0.0.251.240 --next-hop 0.0.251.241 --metric 10

# Lookup destination
ipv8lab route lookup 64496.10.0.0.1
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

# Issue OAuth8 token
ipv8lab zone oauth-issue device-42

# Validate VLAN
ipv8lab zone vlan-check 100

# List services
ipv8lab zone services
```

## multizone

Multi-zone simulation with Zone Server pairs.

```bash
# Initialize multi-zone topology
ipv8lab multizone init --zones 3

# Show topology status
ipv8lab multizone status
```

## bgp8

BGP8 path selection with Cost Factor metric.

```bash
# Initialize BGP8 router
ipv8lab bgp8 init --asn 64496

# Advertise prefix
ipv8lab bgp8 advertise --prefix 0.0.251.240 --next-hop 0.0.251.241

# Show RIB
ipv8lab bgp8 rib

# Best path selection
ipv8lab bgp8 best-path --prefix 0.0.251.240
```

## xlate8

XLATE8 north-south traffic flow.

```bash
# Initialize XLATE8 gateway
ipv8lab xlate8 init

# Translate address
ipv8lab xlate8 translate --src 64496.10.0.0.1

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
# Fragment a large payload
ipv8lab frag fragment --src 64496.10.0.0.1 --dst 64497.10.0.0.2 --size 256 --mtu 64

# Reassemble fragments
ipv8lab frag reassemble fragments.bin

# Show fragmentation info
ipv8lab frag info --json
```

## traceroute

Traceroute8 diagnostic utility.

```bash
# Trace route to destination
ipv8lab traceroute trace --dst 64497.10.0.0.1 --hops 8

# JSON output
ipv8lab traceroute trace --dst 64497.10.0.0.1 --json
```

## nat8

NAT8 address translation gateway.

```bash
# Initialize NAT8 gateway
ipv8lab nat8 init --mode dynamic

# Add static mapping
ipv8lab nat8 add --inside 10.0.0.1 --outside 64496.10.0.0.1

# Show translation table
ipv8lab nat8 table

# Status
ipv8lab nat8 status --json
```

## netflow8

NetFlow8 flow monitoring and telemetry.

```bash
# Start monitoring
ipv8lab netflow8 init

# Show flows
ipv8lab netflow8 flows

# Export telemetry
ipv8lab netflow8 export --format jsonl

# Status
ipv8lab netflow8 status --json
```

## qos

QoS traffic shaping based on TOS field.

```bash
# Initialize QoS engine
ipv8lab qos init

# Classify packet
ipv8lab qos classify --tos 46

# Show queues
ipv8lab qos queues

# Status
ipv8lab qos status --json
```

## cf

CF (Cost Factor) performance dashboard.

```bash
# Compute CF for a path
ipv8lab cf compute --latency 12.5 --bandwidth 1000 --jitter 0.3

# Launch HTML dashboard
ipv8lab cf dashboard --port 8080

# Status
ipv8lab cf status --json
```

## fuzz

Packet fuzzer for protocol security testing.

```bash
# Run fuzzer (1000 iterations)
ipv8lab fuzz run --iterations 1000

# All strategies
ipv8lab fuzz run --strategy all --json

# Show results
ipv8lab fuzz results
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

# Encrypt message
ipv8lab mtls encrypt my-device "secret payload"

# Decrypt message
ipv8lab mtls decrypt my-device <ciphertext>
```

## docker

Docker-based multi-node testbed.

```bash
# Generate testbed config
ipv8lab docker generate --nodes 4 --topology mesh

# Build containers
ipv8lab docker build

# Show status
ipv8lab docker status --json
```

## tui

TUI dashboard powered by Rich Live / Textual.

```bash
# Launch TUI
ipv8lab tui launch

# Status
ipv8lab tui status --json
```

## bench

Performance benchmarks.

```bash
# Run all benchmarks
ipv8lab bench run

# Run specific benchmark
ipv8lab bench run --name address

# JSON output
ipv8lab bench run --json
```

## capture

Packet capture and replay (.iv8cap format).

```bash
# Start capture
ipv8lab capture start -o trace.iv8cap

# Replay capture
ipv8lab capture replay trace.iv8cap

# Show capture info
ipv8lab capture info trace.iv8cap
```

## dashboard

Web UI dashboard (dark theme, JSON API).

```bash
# Launch web dashboard
ipv8lab dashboard serve --port 8080

# Status
ipv8lab dashboard status --json
```

## udp

UDP transport experiments.

```bash
# Run UDP node
ipv8lab udp run --port 9000

# Send packet
ipv8lab udp send --dst 127.0.0.1:9001 --payload "hello"
```

## usage

Address Usage Model table per Section 4.11.

```bash
# Show full address space table
ipv8lab usage show

# JSON output
ipv8lab usage show --json
```

## arp8

ARP8-driven version selection per Section 2.

```bash
# Initialize ARP8
ipv8lab arp8 init

# Resolve address
ipv8lab arp8 resolve 64496.10.0.0.1

# Status
ipv8lab arp8 status --json
```

## interop

Inter-Company Interop and Two-XLATE8 model (Sections 4.6–4.7).

```bash
# Initialize interop
ipv8lab interop init

# Show interop prefix
ipv8lab interop show

# Status
ipv8lab interop status --json
```

## ilink

Interior Link Convention (222.0.0.0/8) per Section 4.10.

```bash
# Initialize interior link
ipv8lab ilink init

# Validate address
ipv8lab ilink validate 222.0.0.1.10.0.0.1

# Status
ipv8lab ilink status --json
```

## socket

Socket API Compatibility mock (AF_INET8) per Section 6.2.

```bash
# Initialize socket mock
ipv8lab socket init

# Create socket
ipv8lab socket create --family AF_INET8 --type SOCK_DGRAM

# Status
ipv8lab socket status --json
```

## cgnat

CGNAT Behaviour simulation per Section 15.

```bash
# Initialize CGNAT
ipv8lab cgnat init

# Translate
ipv8lab cgnat translate --src 10.0.0.1

# Status
ipv8lab cgnat status --json
```

## vpc

Cloud Provider VPC simulation per Section 17.

```bash
# Initialize VPC
ipv8lab vpc init --zone-prefix 127.1.0.0

# Show VPC mapping
ipv8lab vpc show

# Status
ipv8lab vpc status --json
```

## rineprot

RINE Prefix Protection per Section 19.3.

```bash
# Initialize RINE protection
ipv8lab rineprot init

# Check BGP8 advertisement
ipv8lab rineprot bgp8 --prefix 100.0.0.0

# Show traps
ipv8lab rineprot traps --json

# Status
ipv8lab rineprot status --json
```

## ilinkprot

Interior Link Convention Protection per Section 19.4.

```bash
# Initialize filter
ipv8lab ilinkprot init

# Check BGP8 advertisement
ipv8lab ilinkprot bgp8 --prefix 222.0.0.0 --origin 64496

# Filter packet
ipv8lab ilinkprot packet --src 222.0.0.1.10.0.0.1 --dst 64496.10.0.0.1

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

# Check advertisement
ipv8lab prefixenf check --prefix 0.0.251.240 --length 16 --origin 64496

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

# Register ASN
ipv8lab whois8 register --asn 64496 --holder "Example Corp" --rir ARIN

# Register route
ipv8lab whois8 route --asn 64496 --prefix 0.0.251.240 --length 16

# Lookup ASN
ipv8lab whois8 lookup --asn 64496

# Validate route
ipv8lab whois8 validate --asn 64496 --prefix 0.0.251.240

# Anycast lookup
ipv8lab whois8 anycast --prefix 0.0.251.240

# Verify record signature
ipv8lab whois8 verify --asn 64496

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

# Log message
ipv8lab netlog8proto log --severity 6 --facility 1 --message "link up"

# Log security alert
ipv8lab netlog8proto sec-alert --message "spoofed prefix detected" --source 64496

# Log E3 trap
ipv8lab netlog8proto e3-trap --message "interior link leak" --source 222.0.0.1

# Query logs
ipv8lab netlog8proto query --severity 4 --facility 1

# Add alert rule
ipv8lab netlog8proto add-rule --name critical --severity-min 2

# Show alerts
ipv8lab netlog8proto alerts --json

# Export logs
ipv8lab netlog8proto export --format jsonl

# Show header info
ipv8lab netlog8proto header-info

# Status
ipv8lab netlog8proto status --json
```
