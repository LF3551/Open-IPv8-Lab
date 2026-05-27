[← Back to README](../README.md)

# Examples

Sample configs, scripts, and data for Open-IPv8-Lab.

## Files

| File | Description | Used by |
|------|-------------|---------|
| [`two_asn_demo.yaml`](two_asn_demo.yaml) | Two-ASN network topology — 2 hosts, 2 routers, inter-AS routing | `ipv8lab route simulate --config` |
| [`three_asn_mesh.yaml`](three_asn_mesh.yaml) | Three-ASN triangle mesh — 3 hosts, 3 routers, full-mesh peering | `ipv8lab route simulate --config` |
| [`address_examples.txt`](address_examples.txt) | Sample IPv8 addresses in canonical `<RN>-<LA>` and full 8-octet form | Reference |
| [`packet_demo.py`](packet_demo.py) | Build and parse an IPv8 packet using the Python API | `python examples/packet_demo.py` |
| [`routing_demo.py`](routing_demo.py) | Run a routing simulation programmatically (loads `two_asn_demo.yaml`) | `python examples/routing_demo.py` |
| [`udp_demo.py`](udp_demo.py) | Async UDP transport demo — nodes exchange packets over localhost sockets | `python examples/udp_demo.py` |
| [`dns_discovery_demo.py`](dns_discovery_demo.py) | Zone Server discovery via `<RN>.asn.arpa.` / fallback / anycast (§3.4) | `python examples/dns_discovery_demo.py` |
| [`bgp8_demo.py`](bgp8_demo.py) | BGP8 best-path selection across two peers using Cost Factor | `python examples/bgp8_demo.py` |
| [`whois8_demo.py`](whois8_demo.py) | WHOIS8 server/client — ASN register + lookup + route validation | `python examples/whois8_demo.py` |
| [`xlate8_demo.py`](xlate8_demo.py) | XLATE8 north-south flow with DNS8 resolution (§15) | `python examples/xlate8_demo.py` |
| [`nat8_demo.py`](nat8_demo.py) | NAT8 gateway — static + dynamic mappings | `python examples/nat8_demo.py` |
| [`traceroute_demo.py`](traceroute_demo.py) | Traceroute8 across a 4-router linear topology | `python examples/traceroute_demo.py` |
| [`multizone_demo.py`](multizone_demo.py) | Multi-zone simulation with DHCP8 leases per zone (§9) | `python examples/multizone_demo.py` |
| [`netflow8_demo.py`](netflow8_demo.py) | NetFlow8 collector — observe + export flow records | `python examples/netflow8_demo.py` |
| [`fragmentation_demo.py`](fragmentation_demo.py) | Packet fragmentation and reassembly across MTU boundaries (§8) | `python examples/fragmentation_demo.py` |
| [`qos_demo.py`](qos_demo.py) | QoS traffic shaping — priority dequeue by TOS/DSCP (§7) | `python examples/qos_demo.py` |

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

# Python scripts (network primitives)
python examples/packet_demo.py
python examples/routing_demo.py
python examples/udp_demo.py
python examples/dns_discovery_demo.py

# Python scripts (protocols & services)
python examples/bgp8_demo.py
python examples/whois8_demo.py
python examples/xlate8_demo.py
python examples/nat8_demo.py
python examples/traceroute_demo.py
python examples/multizone_demo.py
python examples/netflow8_demo.py
python examples/fragmentation_demo.py
python examples/qos_demo.py
```
