#!/usr/bin/env python3
# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""QoS traffic shaping demo (Section 7)."""

from ipv8lab.address import IPv8Address
from ipv8lab.packet import IPv8Packet
from ipv8lab.qos import TrafficShaper, QoSPolicy, TrafficClass, classify

shaper = TrafficShaper(policy=QoSPolicy.PRIORITY)

# tos: 0 = BE, 184 = EF (DSCP 46), 72 = AF21 (DSCP 18), 104 = AF31 (DSCP 26)
packets = [
    ("64496-10.0.1.10", "64497-10.0.1.1",   0),
    ("64496-10.0.1.20", "64497-10.0.1.1", 184),
    ("64496-10.0.1.30", "64497-10.0.1.1",  72),
    ("64496-10.0.1.10", "64497-10.0.1.1", 104),
]
for src, dst, tos in packets:
    pkt = IPv8Packet(
        src=IPv8Address.parse(src),
        dst=IPv8Address.parse(dst),
        tos=tos,
        payload=b"data",
    )
    shaper.enqueue(pkt)

print("Priority dequeue order:")
while True:
    p = shaper.dequeue()
    if p is None:
        break
    print(f"  {classify(p).name}  tos={p.tos}")
