#!/usr/bin/env python3
# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""NAT8 gateway demo (Section 15)."""

from ipv8lab.address import IPv8Address
from ipv8lab.nat8 import NATGateway, NATMode
from ipv8lab.packet import IPv8Packet

gw = NATGateway(mode=NATMode.STATIC)
gw.add_static_mapping("127.1.0.0.10.0.1.10", "64496-10.0.1.100")

pkt = IPv8Packet(
    src=IPv8Address.parse("127.1.0.0.10.0.1.10"),
    dst=IPv8Address.parse("64497-10.0.1.1"),
    payload=b"static-test",
)
out = gw.translate_egress(pkt)
print(f"Static NAT: {pkt.src.canonical} → {out.src.canonical if out else 'FAIL'}")

gw_dyn = NATGateway(mode=NATMode.DYNAMIC)
gw_dyn.add_pool_address("64496-10.0.1.200")
gw_dyn.add_pool_address("64496-10.0.1.201")

for h in ["127.1.0.0.10.0.1.20", "127.1.0.0.10.0.1.21"]:
    p = IPv8Packet(
        src=IPv8Address.parse(h),
        dst=IPv8Address.parse("64497-10.0.1.1"),
        payload=b"dyn",
    )
    gw_dyn.translate_egress(p)

print(f"Dynamic NAT: {gw_dyn.mapping_count} mappings allocated")
