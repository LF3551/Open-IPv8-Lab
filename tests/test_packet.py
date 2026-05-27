# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for ipv8lab.packet."""

import pytest

from ipv8lab.address import IPv8Address
from ipv8lab.errors import ChecksumMismatchError, InvalidPacketError
from ipv8lab.packet import HEADER_SIZE, IPV8_VERSION, IPv8Packet, PROTO_EXPERIMENTAL


class TestPacketBuildParse:
    def test_roundtrip(self):
        src = IPv8Address.parse("64496-192.0.2.1")
        dst = IPv8Address.parse("64497-198.51.100.7")
        pkt = IPv8Packet(src=src, dst=dst, payload=b"hello")
        raw = pkt.to_bytes()
        restored = IPv8Packet.from_bytes(raw)
        assert restored.src == src
        assert restored.dst == dst
        assert restored.payload == b"hello"
        assert restored.version == IPV8_VERSION
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
        src = IPv8Address.parse("64496-10.0.0.1")
        dst = IPv8Address.parse("64497-10.0.0.2")
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
        src = IPv8Address.parse("64496-10.0.0.1")
        dst = IPv8Address.parse("64497-10.0.0.2")
        pkt = IPv8Packet(src=src, dst=dst, payload=b"long payload data here")
        raw = pkt.to_bytes()
        # cut off part of the payload
        with pytest.raises(InvalidPacketError):
            IPv8Packet.from_bytes(raw[:HEADER_SIZE + 2])


class TestPacketHeaderFields:
    """Test IPv8 header fields per Section 5.1."""

    def test_version_is_8(self):
        src = IPv8Address.parse("64496-10.0.0.1")
        dst = IPv8Address.parse("64497-10.0.0.2")
        pkt = IPv8Packet(src=src, dst=dst)
        raw = pkt.to_bytes()
        # First nibble of first byte is version
        assert (raw[0] >> 4) == 8

    def test_ihl_is_7(self):
        src = IPv8Address.parse("64496-10.0.0.1")
        dst = IPv8Address.parse("64497-10.0.0.2")
        pkt = IPv8Packet(src=src, dst=dst)
        raw = pkt.to_bytes()
        # Lower nibble of first byte is IHL
        assert (raw[0] & 0x0F) == 7

    def test_header_size_28_bytes(self):
        assert HEADER_SIZE == 28

    def test_tos_roundtrip(self):
        src = IPv8Address.parse("64496-10.0.0.1")
        dst = IPv8Address.parse("64497-10.0.0.2")
        pkt = IPv8Packet(src=src, dst=dst, tos=0x28)
        restored = IPv8Packet.from_bytes(pkt.to_bytes())
        assert restored.tos == 0x28

    def test_identification_roundtrip(self):
        src = IPv8Address.parse("64496-10.0.0.1")
        dst = IPv8Address.parse("64497-10.0.0.2")
        pkt = IPv8Packet(src=src, dst=dst, identification=12345)
        restored = IPv8Packet.from_bytes(pkt.to_bytes())
        assert restored.identification == 12345

    def test_flags_and_fragment_offset(self):
        src = IPv8Address.parse("64496-10.0.0.1")
        dst = IPv8Address.parse("64497-10.0.0.2")
        pkt = IPv8Packet(src=src, dst=dst, flags=0x02, fragment_offset=100)
        restored = IPv8Packet.from_bytes(pkt.to_bytes())
        assert restored.flags == 0x02
        assert restored.fragment_offset == 100

    def test_total_length_in_wire(self):
        import struct
        src = IPv8Address.parse("64496-10.0.0.1")
        dst = IPv8Address.parse("64497-10.0.0.2")
        pkt = IPv8Packet(src=src, dst=dst, payload=b"test")
        raw = pkt.to_bytes()
        total_length = struct.unpack("!H", raw[2:4])[0]
        assert total_length == HEADER_SIZE + 4

    def test_src_dst_split_in_wire(self):
        """Verify ASN prefix and host are separate 32-bit fields in wire format."""
        import struct
        src = IPv8Address.parse("64496-192.0.2.1")
        dst = IPv8Address.parse("64497-198.51.100.7")
        pkt = IPv8Packet(src=src, dst=dst)
        raw = pkt.to_bytes()
        # Bytes 12-15: src ASN prefix, 16-19: src host, 20-23: dst ASN, 24-27: dst host
        src_asn = struct.unpack("!I", raw[12:16])[0]
        src_host = struct.unpack("!I", raw[16:20])[0]
        dst_asn = struct.unpack("!I", raw[20:24])[0]
        dst_host = struct.unpack("!I", raw[24:28])[0]
        assert src_asn == 64496
        assert src_host == (192 << 24 | 0 << 16 | 2 << 8 | 1)
        assert dst_asn == 64497
        assert dst_host == (198 << 24 | 51 << 16 | 100 << 8 | 7)
