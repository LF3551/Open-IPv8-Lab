#!/usr/bin/env python3
# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""NetFlow8 flow collector demo."""

from ipv8lab.address import IPv8Address
from ipv8lab.netflow8 import FlowCollector
from ipv8lab.packet import IPv8Packet

col = FlowCollector(active_timeout=120.0, idle_timeout=15.0)

flows_spec = [
    ("64496-10.0.1.10", "64497-10.0.1.1",  6, 12345,  80, 5),
    ("64496-10.0.1.20", "64497-10.0.1.1",  6, 23456, 443, 3),
    ("64496-10.0.1.10", "64498-10.0.1.5", 17,  5000,  53, 2),
]
for src, dst, proto, sport, dport, count in flows_spec:
    pkt = IPv8Packet(
        src=IPv8Address.parse(src),
        dst=IPv8Address.parse(dst),
        protocol=proto,
        payload=b"data",
    )
    for _ in range(count):
        col.observe(pkt, src_port=sport, dst_port=dport)

records = col.export_all()
print(f"Exported {len(records)} flows")
for rec in records:
    k = rec.key
    print(f"  {k.src_addr}:{k.src_port} → {k.dst_addr}:{k.dst_port}  "
          f"proto={k.protocol}  packets={rec.packets}")
