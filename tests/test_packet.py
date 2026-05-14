# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for ipv8lab.packet."""

import pytest

from ipv8lab.address import IPv8Address
from ipv8lab.errors import ChecksumMismatchError, InvalidPacketError
from ipv8lab.packet import HEADER_SIZE, IPv8Packet, PROTO_EXPERIMENTAL


class TestPacketBuildParse:
    def test_roundtrip(self):
        src = IPv8Address.parse("64496.192.0.2.1")
        dst = IPv8Address.parse("64497.198.51.100.7")
        pkt = IPv8Packet(src=src, dst=dst, payload=b"hello")
        raw = pkt.to_bytes()
        restored = IPv8Packet.from_bytes(raw)
        assert restored.src == src
        assert restored.dst == dst
        assert restored.payload == b"hello"
        assert restored.version == 1
        assert restored.ttl == 64
        assert restored.protocol == PROTO_EXPERIMENTAL

    def test_empty_payload(self):
        src = IPv8Address.parse("0.0.0.0.1.1.1.1")
        dst = IPv8Address.parse("0.0.0.0.2.2.2.2")
        pkt = IPv8Packet(src=src, dst=dst)
        raw = pkt.to_bytes()
        assert len(raw) == HEADER_SIZE
        restored = IPv8Packet.from_bytes(raw)
        assert restored.payload == b""

    def test_checksum_mismatch(self):
        src = IPv8Address.parse("64496.10.0.0.1")
        dst = IPv8Address.parse("64497.10.0.0.2")
        pkt = IPv8Packet(src=src, dst=dst, payload=b"data")
        raw = bytearray(pkt.to_bytes())
        # corrupt one byte
        raw[HEADER_SIZE] ^= 0xFF
        with pytest.raises(ChecksumMismatchError):
            IPv8Packet.from_bytes(bytes(raw))

    def test_too_short(self):
        with pytest.raises(InvalidPacketError):
            IPv8Packet.from_bytes(b"\x00" * 10)

    def test_truncated_payload(self):
        src = IPv8Address.parse("64496.10.0.0.1")
        dst = IPv8Address.parse("64497.10.0.0.2")
        pkt = IPv8Packet(src=src, dst=dst, payload=b"long payload data here")
        raw = pkt.to_bytes()
        # cut off part of the payload
        with pytest.raises(InvalidPacketError):
            IPv8Packet.from_bytes(raw[:HEADER_SIZE + 2])
