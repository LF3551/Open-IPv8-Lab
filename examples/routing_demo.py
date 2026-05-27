#!/usr/bin/env python3
# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Routing simulation demo using the two-ASN config."""

from pathlib import Path

from ipv8lab.simulator import NetworkSimulator

config = Path(__file__).parent / "two_asn_demo.yaml"
sim = NetworkSimulator.load_config(config)

print(f"Network: {sim.name}")
print(f"Nodes:   {', '.join(sim.nodes)}")
print()

trace = sim.send("node-a", "64497-198.51.100.7", "hello")
print("Trace:")
for line in trace:
    print(f"  {line}")
