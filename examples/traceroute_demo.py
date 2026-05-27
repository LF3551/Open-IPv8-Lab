#!/usr/bin/env python3
# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Traceroute8 demo: build a small topology and trace a path."""

from ipv8lab.traceroute8 import Topology, traceroute

topo = Topology()
topo.add_router("R0", "64496-10.0.1.1", routes={"*": "R1"})
topo.add_router("R1", "64497-10.0.1.1", routes={"*": "R2"})
topo.add_router("R2", "64498-10.0.1.1", routes={"64496": "R0", "*": "R3"})
topo.add_router("R3", "64499-10.0.1.1", routes={})

result = traceroute(topo, "64496-10.0.1.1", "64499-10.0.1.1")

print(f"Traceroute {result.src} → {result.dst}")
if result.error:
    print(f"Error: {result.error}")
else:
    for hop in result.hops:
        print(f"  TTL {hop.ttl}: {hop.address} ({hop.router_name})  {hop.rtt_ms:.2f} ms")
    print(f"Completed: {result.completed}  hops: {result.hop_count}")
