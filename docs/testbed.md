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
