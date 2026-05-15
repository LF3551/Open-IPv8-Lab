# Examples

Sample configs, scripts, and data for Open-IPv8-Lab.

## Files

| File | Description | Used by |
|------|-------------|---------|
| [`two_asn_demo.yaml`](two_asn_demo.yaml) | Two-ASN network topology — 2 hosts, 2 routers, inter-AS routing | `ipv8lab route simulate --config` |
| [`three_asn_mesh.yaml`](three_asn_mesh.yaml) | Three-ASN triangle mesh — 3 hosts, 3 routers, full-mesh peering | `ipv8lab route simulate --config` |
| [`address_examples.txt`](address_examples.txt) | Sample IPv8 addresses in ASN dot notation and full 8-octet format | Reference |
| [`packet_demo.py`](packet_demo.py) | Build and parse an IPv8 packet using the Python API | `python examples/packet_demo.py` |
| [`routing_demo.py`](routing_demo.py) | Run a routing simulation programmatically (loads `two_asn_demo.yaml`) | `python examples/routing_demo.py` |
| [`udp_demo.py`](udp_demo.py) | Async UDP transport demo — nodes exchange packets over localhost sockets | `python examples/udp_demo.py` |

## YAML topology format

Network configs use the following structure:

```yaml
network:
  name: <topology-name>

nodes:
  - name: <host-name>
    address: <ASN.a.b.c.d>    # IPv8 address in ASN dot notation
    type: host

routers:
  - name: <router-name>
    asn: <ASN>                 # 32-bit Autonomous System Number

links:
  - from: <node-or-router>
    to: <node-or-router>

routes:
  - router: <router-name>
    destination_prefix: "<p1.p2.p3.p4>"   # 4-octet routing prefix
    next_hop: <router-name>
    interface: <interface-name>
```

## Quick run

```bash
# Route simulation with two ASNs
ipv8lab route simulate --config examples/two_asn_demo.yaml

# Route simulation with three-ASN mesh
ipv8lab route simulate --config examples/three_asn_mesh.yaml

# Python scripts
python examples/packet_demo.py
python examples/routing_demo.py
```
