#!/usr/bin/env python3
# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Packet fragmentation & reassembly demo (Section 8)."""

from ipv8lab.address import IPv8Address
from ipv8lab.fragmentation import fragment, fragment_and_reassemble
from ipv8lab.packet import IPv8Packet

scenarios = [
    ("Small (100B, MTU=1500)",    100, 1500),
    ("Exact fit (1472B, MTU=1500)", 1472, 1500),
    ("Over MTU (1473B, MTU=1500)", 1473, 1500),
    ("Large (5000B, MTU=1500)",   5000, 1500),
]
for label, size, mtu in scenarios:
    payload = (bytes(range(256)) * ((size // 256) + 1))[:size]
    pkt = IPv8Packet(
        src=IPv8Address.parse("64496-10.0.1.1"),
        dst=IPv8Address.parse("64497-10.0.1.100"),
        payload=payload,
    )
    frags = fragment(pkt, mtu)
    reassembled = fragment_and_reassemble(pkt, mtu)
    ok = reassembled.payload == pkt.payload
    print(f"{label}: {len(frags)} fragments, match={ok}")
