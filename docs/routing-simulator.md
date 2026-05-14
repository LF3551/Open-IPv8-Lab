# Routing Simulator

The routing simulator demonstrates IPv8-style prefix-based routing in memory.

## Route table

A route table maps destination prefixes to next hops:

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

## Lookup logic

1. Extract the first 4 octets of the destination address as the routing prefix
2. Search for an exact prefix match in the route table
3. If prefix is `0.0.0.0`, the address is IPv4-compatible
4. If prefix starts with `127`, the address is internal zone
5. If a matching route is found, return the next hop
6. If no route matches, fall back to a `0.0.0.0` default route
7. If no default route exists, raise `NoRouteFoundError`

## Network simulation

A full network simulation loads a YAML config describing nodes, routers, links, and routes:

```bash
ipv8lab route simulate --config examples/two_asn_demo.yaml
```

The simulator traces the packet path through the network and displays each hop.
