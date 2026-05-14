#!/usr/bin/env python3
# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Packet build & parse demo."""

from ipv8lab.address import IPv8Address
from ipv8lab.packet import IPv8Packet

src = IPv8Address.parse("64496.192.0.2.1")
dst = IPv8Address.parse("64497.198.51.100.7")

pkt = IPv8Packet(src=src, dst=dst, payload=b"hello from IPv8 Lab!")
raw = pkt.to_bytes()

print(f"Built packet: {len(raw)} bytes, checksum=0x{pkt.checksum:08X}")

restored = IPv8Packet.from_bytes(raw)
print(f"Parsed back:  src={restored.src} dst={restored.dst}")
print(f"Payload:      {restored.payload.decode()}")
