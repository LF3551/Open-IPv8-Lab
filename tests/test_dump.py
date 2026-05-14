# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for ipv8lab.dump — hexdump and summary utilities."""

from ipv8lab.address import IPv8Address
from ipv8lab.dump import address_summary, hexdump, packet_summary
from ipv8lab.packet import IPv8Packet


class TestHexdump:
    def test_basic(self):
        result = hexdump(b"Hello, world!")
        assert "48 65 6C 6C 6F" in result
        assert "|Hello, world!|" in result

    def test_empty(self):
        assert hexdump(b"") == ""

    def test_multi_line(self):
        data = bytes(range(32))
        lines = hexdump(data).splitlines()
        assert len(lines) == 2
        assert lines[0].startswith("00000000")
        assert lines[1].startswith("00000010")

    def test_non_printable(self):
        result = hexdump(b"\x00\x01\x02\x7f")
        assert "|....|" in result


class TestPacketSummary:
    def test_summary_fields(self):
        src = IPv8Address.parse("64496.10.0.0.1")
        dst = IPv8Address.parse("64497.10.0.0.2")
        pkt = IPv8Packet(src=src, dst=dst, payload=b"test")
        pkt.to_bytes()  # compute checksum
        s = packet_summary(pkt)

        assert s["src"] == "0.0.251.240.10.0.0.1"
        assert s["dst"] == "0.0.251.241.10.0.0.2"
        assert s["src_asn"] == 64496
        assert s["dst_asn"] == 64497
        assert s["payload_length"] == 4
        assert s["payload_text"] == "test"
        assert s["version"] == 8


class TestAddressSummary:
    def test_asn_notation(self):
        s = address_summary("64496.192.0.2.1")
        assert s["asn"] == 64496
        assert s["format"] == "ASN dot notation"
        assert s["full_notation"] == "0.0.251.240.192.0.2.1"

    def test_full_notation(self):
        s = address_summary("0.0.0.0.8.8.8.8")
        assert s["format"] == "Full 8-octet notation"
        assert s["type"] == "IPv4-compatible"
