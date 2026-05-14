# Routing (Sections 8.7, 8.8)

Per [draft-thain-ipv8-00](https://www.ietf.org/archive/id/draft-thain-ipv8-00.html) Sections 8.7 and 8.8.

## Two-tier routing table (Section 8.7)

| Tier | Scope | Lookup key | Purpose |
|------|-------|------------|---------|
| 1 | Global | r.r.r.r | Routes to correct AS border router |
| 2 | Local | n.n.n.n | Identical to existing IPv4 routing table |

When `r.r.r.r = 0.0.0.0` the Tier 1 lookup is bypassed — standard IPv4 rules apply.

Tier 2 supports `/8`, `/16`, `/24` prefix matching.

## Route table config

```yaml
routes:
  - destination_prefix: "0.0.251.240"
    next_hop: "router-a"
    interface: "lab0"

  - destination_prefix: "0.0.251.241"
    next_hop: "router-b"
    interface: "lab1"

  - destination_prefix: "0.0.0.0"
    next_hop: "ipv4-gateway"
    interface: "ipv4"
```

## VRF — Virtual Routing and Forwarding (Section 8.8)

VRF is mandatory for all IPv8 L3 devices:

| VRF | VLAN | Purpose |
|-----|------|---------|
| management | 4090 | Device management traffic |
| oob | 4091 | Out-of-band management |
| default | — | Global/default routing table |

VRF isolation is a routing table property — each VRF has its own independent `RouteTable`.

## Mesh network simulation

The simulator supports multi-hop mesh topologies with cycle detection:

```bash
ipv8lab route simulate --config examples/three_asn_mesh.yaml
```

Packet tracing shows each hop through the network.
