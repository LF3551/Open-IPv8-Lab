# Routing (Sections 8.7, 8.8)

Per [draft-thain-ipv8-02](https://www.ietf.org/archive/id/draft-thain-ipv8-02.html) Sections 8.7 and 8.8.

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

## BGP8 path selection with CF metric (Section 8.4)

BGP8PathSelector maintains a per-prefix RIB and selects the best path using accumulated Cost Factor:

| Step | Criterion |
|------|-----------|
| 1 | Filter invalid prefixes (/16 min for eBGP8), reject AS-path loops |
| 2 | Lowest `CF_total = CF_external + CF_intrazone` |
| 3 | Shortest AS-path (tie-break) |
| 4 | Lowest origin ASN (further tie-break) |

CF anomalies are flagged when measured RTT is faster than the physics floor (speed of light in fibre over great-circle distance).

Withdraw a prefix → second-best path automatically becomes best.
