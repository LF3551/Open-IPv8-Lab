[← Back to README](../README.md)

# Python API

Open-IPv8-Lab can be used as a Python library. All public modules live under `ipv8lab.*`.

```python
pip install -e ".[dev]"
```

## Table of Contents

- [Addressing](#addressing)
- [Packets](#packets)
- [Routing](#routing)
- [Network Simulation](#network-simulation)
- [Zone Server (OAuth8, ACL8, DHCP8)](#zone-server)
- [BGP8 Path Selection](#bgp8-path-selection)
- [Cost Factor Metric](#cost-factor-metric)
- [XLATE8 Traffic Flow](#xlate8-traffic-flow)
- [ICMPv8](#icmpv8)
- [Fragmentation](#fragmentation)
- [Packet Capture](#packet-capture)
- [PCAP Export (Wireshark)](#pcap-export)
- [Security Filtering](#security-filtering)
- [Benchmarks](#benchmarks)
- [Plugin System](#plugin-system)

---

## Addressing

```python
from ipv8lab.address import IPv8Address, asn_to_prefix, prefix_to_asn

# Parse from ASN dot notation or full 8-octet format
addr = IPv8Address.parse("64496.192.0.2.1")
addr2 = IPv8Address.parse("0.0.251.240.192.0.2.1")

# Properties
addr.asn              # 64496
addr.routing_prefix   # (0, 0, 251, 240)
addr.host_part        # (192, 0, 2, 1)
addr.prefix_str       # "0.0.251.240"
addr.host_str         # "192.0.2.1"
addr.full_notation    # "0.0.251.240.192.0.2.1"
addr.asn_notation     # "64496.192.0.2.1"
addr.address_class    # "unicast"

# Classification
addr.is_unicast()          # True
addr.is_multicast()        # False
addr.is_broadcast()        # False
addr.is_rine_prefix()      # False
addr.is_internal_zone()    # False
addr.is_interior_link()    # False
addr.is_interop_prefix()   # False

# Serialization
n = addr.to_int()                    # 64-bit integer
addr3 = IPv8Address.from_int(n)      # Round-trip

# ASN ↔ prefix conversion
prefix = asn_to_prefix(64496)        # (0, 0, 251, 240)
asn = prefix_to_asn((0, 0, 251, 240))  # 64496
```

---

## Packets

```python
from ipv8lab.address import IPv8Address
from ipv8lab.packet import IPv8Packet, PROTO_UDP, PROTO_TCP

# Build a packet
pkt = IPv8Packet(
    src=IPv8Address.parse("64496.192.0.2.1"),
    dst=IPv8Address.parse("64497.198.51.100.7"),
    payload=b"hello",
    ttl=64,
    protocol=PROTO_UDP,
    tos=0,
)

# Serialize to bytes (28-byte header + payload)
raw = pkt.to_bytes()
len(raw)  # 33 (28 header + 5 payload)

# Parse from bytes
pkt2 = IPv8Packet.from_bytes(raw)
pkt2.src.asn_notation   # "64496.192.0.2.1"
pkt2.payload            # b"hello"
pkt2.checksum           # CRC32 (read-only)

# Skip checksum verification
pkt3 = IPv8Packet.from_bytes(raw, verify=False)
```

---

## Routing

```python
from ipv8lab.route import Route, RouteTable, TwoTierRouteTable

# Manual route table
rt = RouteTable()
rt.add_route(Route(destination_prefix="0.0.251.241", next_hop="router-b", interface="eth0"))
rt.add_route(Route(destination_prefix="0.0.251.240", next_hop="router-a", interface="eth1"))

route = rt.find_route("0.0.251.241.198.51.100.7")
route.next_hop       # "router-b"
route.interface      # "eth0"

# Load from YAML config
rt2 = RouteTable.load_from_yaml("examples/two_asn_demo.yaml")

# Two-tier routing (§8.7)
tt = TwoTierRouteTable()
tt.tier1.add_route(Route(destination_prefix="0.0.251.241", next_hop="border-r", interface="wan0"))
route = tt.find_route("64497.198.51.100.7")
```

---

## Network Simulation

```python
from ipv8lab.simulator import NetworkSimulator

# Load topology from YAML
sim = NetworkSimulator.load_config("examples/two_asn_demo.yaml")

# Send a packet and get trace
trace = sim.send("node-a", "64497.198.51.100.7", "hello")
for hop in trace:
    print(hop)
# node-a → router-a → router-b → node-b
```

---

## Zone Server

```python
from ipv8lab.zoneserver import (
    ZoneServer, ZoneServerRole, make_zone_server_pair,
    ZoneService, ZoneServiceType,
    ACL8Rule, ACL8Action,
)

# Create primary + secondary pair
primary, secondary = make_zone_server_pair("127.1.0.0")

# Register a service
primary.register_service(ZoneService(
    service_type=ZoneServiceType.DNS8,
    endpoint="127.1.0.254:53",
))
primary.list_services()  # [ZoneService(...)]

# OAuth8 — issue and validate tokens
primary.oauth8_cache.register_key("key-1", b"supersecret")
token = primary.oauth8_cache.issue_token(
    key_id="key-1",
    subject="device-42",
    issuer="zone-127.1.0.0",
    audience="zone-services",
    scopes=("read", "write"),
)

result = primary.authenticate_device(token)
result.is_valid   # True
result.token.subject  # "device-42"

# ACL8 — east-west access control
primary.acl8_engine.add_rule(ACL8Rule(
    source="64496.10.0.1.1",
    destination="64496.10.0.1.2",
    action=ACL8Action.PERMIT,
    description="Allow host-to-host",
))

check = primary.authorize_traffic("64496.10.0.1.1", "64496.10.0.1.2")
check.is_permitted  # True
```

---

## BGP8 Path Selection

```python
from ipv8lab.bgp8_selection import BGP8PathSelector, build_advertisement
from ipv8lab.cost_factor import CFComponents

selector = BGP8PathSelector(local_asn=64496)

# Build advertisement with CF components
adv1, cf1 = build_advertisement(
    prefix="0.0.251.241",
    origin_asn=64497,
    as_path=(64497,),
    cf_components=CFComponents(rtt=0.1, packet_loss=0.02),
)

adv2, cf2 = build_advertisement(
    prefix="0.0.251.241",
    origin_asn=64498,
    as_path=(64498, 64497),
    cf_components=CFComponents(rtt=0.3, packet_loss=0.05),
)

# Receive advertisements
selector.receive_advertisement(adv1, hop_cfs=(cf1,))
selector.receive_advertisement(adv2, hop_cfs=(cf2,))

# Select best path (lowest CF total)
result = selector.select("0.0.251.241")
result.best.advertisement.origin_asn  # 64497 (lower CF)
result.best.accumulated_cf            # CF score
result.has_anomalies                  # False
```

---

## Cost Factor Metric

```python
from ipv8lab.cost_factor import (
    CFComponents, compute_cf, accumulate_cf, select_best_path,
    great_circle_distance_km, physics_floor_ms, is_cf_anomaly,
)

# Compute CF from 7 normalized components (0.0–1.0)
components = CFComponents(
    rtt=0.15,
    packet_loss=0.02,
    congestion=0.10,
    stability=0.05,
    capacity=0.20,
    economic=0.01,
    geographic=0.30,
)
cf = compute_cf(components)  # Weighted integer score

# Accumulate CF across hops
total = accumulate_cf([10, 20, 15])  # Saturating addition

# Physics floor — minimum RTT based on fibre optics
dist = great_circle_distance_km(52.52, 13.40, 40.71, -74.01)  # Berlin → NYC
floor = physics_floor_ms(dist)  # Minimum possible RTT in ms

# Anomaly detection — measured RTT below physics floor
is_cf_anomaly(measured_rtt_ms=20.0, distance_km=dist)  # True if impossible

# Select best from candidates
best = select_best_path({"path-a": 25, "path-b": 42, "path-c": 18})  # "path-c"
```

---

## XLATE8 Traffic Flow

```python
from ipv8lab.address import IPv8Address
from ipv8lab.xlate8_flow import NorthSouthFlow
from ipv8lab.dns_a8 import A8Record

# Set up a north-south flow
flow = NorthSouthFlow(zone_prefix="127.1.0.0", external_asn=64496)

# Register DNS A8 record
flow.dns.add_record(A8Record(
    name="example.v8",
    address=IPv8Address.parse("64496.198.51.100.1"),
))

# Full egress flow: DNS lookup → XLATE8 entry → translate
internal = IPv8Address.parse("64496.10.0.1.5")
egress_pkt = flow.egress_flow("example.v8", internal)

# Full round-trip
egress, ingress = flow.round_trip("example.v8", internal)

# Check events
for event in flow.events:
    print(f"{event.step}: {'OK' if event.success else 'FAIL'}")
```

---

## ICMPv8

```python
from ipv8lab.address import IPv8Address
from ipv8lab.icmpv8 import (
    echo_request, echo_reply, destination_unreachable, time_exceeded,
    ICMPv8Type, UnreachableCode,
)

src = IPv8Address.parse("64496.10.0.1.1")
dst = IPv8Address.parse("64497.10.0.2.1")

# Ping
req = echo_request(src, dst, identifier=1, sequence=1, payload=b"ping")
rep = echo_reply(req)
rep.msg_type  # ICMPv8Type.ECHO_REPLY

# Unreachable
unreach = destination_unreachable(src, dst, code=UnreachableCode.HOST_UNREACHABLE)

# TTL exceeded
exceeded = time_exceeded(src, dst)

# Serialize / deserialize
raw = req.to_bytes()
msg = req.from_bytes(raw, src, dst)
```

---

## Fragmentation

```python
from ipv8lab.address import IPv8Address
from ipv8lab.packet import IPv8Packet
from ipv8lab.fragmentation import (
    fragment, needs_fragmentation, Reassembler, FLAG_DF,
)

pkt = IPv8Packet(
    src=IPv8Address.parse("64496.10.0.1.1"),
    dst=IPv8Address.parse("64497.10.0.2.1"),
    payload=b"A" * 2000,
)

# Check and fragment
needs_fragmentation(pkt, mtu=576)  # True

fragments = fragment(pkt, mtu=576)
len(fragments)  # Multiple fragments

# Reassemble
reasm = Reassembler()
result = None
for frag in fragments:
    result = reasm.process(frag)
result.payload == pkt.payload  # True

# Don't Fragment flag
pkt2 = IPv8Packet(
    src=pkt.src, dst=pkt.dst,
    payload=b"small",
    flags=FLAG_DF,
)
```

---

## Packet Capture

```python
from ipv8lab.address import IPv8Address
from ipv8lab.packet import IPv8Packet
from ipv8lab.capture import PacketCapture

cap = PacketCapture()
cap.start()

# Capture packets
for i in range(5):
    pkt = IPv8Packet(
        src=IPv8Address.parse("64496.10.0.1.1"),
        dst=IPv8Address.parse("64497.10.0.2.1"),
        payload=f"msg-{i}".encode(),
    )
    cap.capture(pkt)

cap.count  # 5

# Save and load (.iv8cap format)
cap.save("demo.iv8cap")
cap2 = PacketCapture.load("demo.iv8cap")
cap2.count  # 5
```

---

## PCAP Export

```python
from ipv8lab.pcap_export import (
    PcapWriter, PcapReader, generate_lua_dissector, save_lua_dissector,
)
from ipv8lab.capture import PacketCapture

# Convert capture to Wireshark PCAP
cap = PacketCapture.load("demo.iv8cap")

writer = PcapWriter()
writer.add_capture(cap)
stats = writer.save("demo.pcap")
stats.packets  # 5

# Read PCAP
reader = PcapReader.from_file("demo.pcap")
reader.packet_count  # 5

# Generate Wireshark Lua dissector
save_lua_dissector("ipv8_dissector.lua")
```

---

## Security Filtering

```python
from ipv8lab.address import IPv8Address
from ipv8lab.packet import IPv8Packet
from ipv8lab.security import IngressFilter, Severity

# Set up border router filter for external peer ASN 64497
filt = IngressFilter(peer_asn=64497, is_external=True)

# Check a packet — source claims ASN 64496 but arrives from 64497 peer
pkt = IPv8Packet(
    src=IPv8Address.parse("64496.10.0.1.1"),  # Spoofed!
    dst=IPv8Address.parse("64497.10.0.2.1"),
)

violations = filt.check(pkt)
for v in violations:
    print(f"[{v.severity}] §{v.section}: {v.message}")
# [SEC-ALERT] §18.1: ASN spoofing detected
```

---

## Benchmarks

```python
from ipv8lab.benchmark import run_all, bench_address_parse

# Run all 6 benchmarks
results = run_all(iterations=10_000)
for r in results:
    print(f"{r.name}: {r.ops_per_second:,.0f} ops/s ({r.us_per_op:.1f} µs/op)")

# Run a single benchmark
r = bench_address_parse(iterations=50_000)
r.total_seconds  # Wall time
```

---

## Plugin System

```python
from ipv8lab.plugin import PluginRegistry, PluginInfo
from ipv8lab.packet import IPv8Packet

registry = PluginRegistry()

# Register a plugin
registry.register_plugin(PluginInfo(
    name="my-logger",
    version="1.0.0",
    description="Log all packets",
))

# Add a packet hook (called on every packet)
def log_packet(packet: IPv8Packet, node_name: str) -> IPv8Packet | None:
    print(f"[{node_name}] {packet.src} → {packet.dst}")
    return packet  # Return None to drop

registry.add_packet_hook(log_packet)

# Add an event hook
def on_event(event: str, data: dict) -> None:
    print(f"Event: {event} — {data}")

registry.add_event_hook(on_event)

# Apply hooks
pkt = IPv8Packet(src=..., dst=..., payload=b"test")
result = registry.apply_packet_hooks(pkt, "node-a")

# Emit events
registry.emit_event("link_up", {"interface": "eth0"})
```
