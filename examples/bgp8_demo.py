#!/usr/bin/env python3
# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""BGP8 best-path selection demo (Section 19)."""

from ipv8lab.bgp8_selection import BGP8PathSelector, build_advertisement
from ipv8lab.companions import BGP8Peer
from ipv8lab.cost_factor import CFComponents

selector = BGP8PathSelector(local_asn=64496)
selector.add_peer(BGP8Peer(asn=64497, address="64497-10.0.1.1"))
selector.add_peer(BGP8Peer(asn=64498, address="64498-10.0.1.1"))

adv1, cf1 = build_advertisement(
    prefix="64497-0.0.0.0/8", origin_asn=64497,
    as_path=(64497,), next_hop="64497-10.0.1.1",
    cf_components=CFComponents(rtt=0.1, packet_loss=0.05),
    prefix_length=8,
)
selector.receive_advertisement(adv1, hop_cfs=(cf1,))

adv2, cf2 = build_advertisement(
    prefix="64497-0.0.0.0/8", origin_asn=64497,
    as_path=(64498, 64497), next_hop="64498-10.0.1.1",
    cf_components=CFComponents(rtt=0.3, packet_loss=0.1),
    prefix_length=8,
)
selector.receive_advertisement(adv2, hop_cfs=(cf2,))

for prefix, result in selector.select_all().items():
    if result.best:
        print(f"Prefix {prefix}: best via ASN {result.best.advertisement.origin_asn} "
              f"(CF={result.best.accumulated_cf})")
