# Local Testbed

The testbed feature allows running a simulated multi-node IPv8 network locally.

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
2. `router-a` reads the destination prefix
3. `router-a` forwards to `router-b`
4. `router-b` delivers the packet to `node-b`
5. `node-b` receives the payload

### Running the demo

```bash
ipv8lab route simulate --config examples/two_asn_demo.yaml
```

Or as a Python script:

```bash
python examples/routing_demo.py
```

## Future: UDP transport

In a future version, nodes will run as separate processes communicating over UDP:

```
node-a process → UDP → router-a process → UDP → router-b process → UDP → node-b process
```
