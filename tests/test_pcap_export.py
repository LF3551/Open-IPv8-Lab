# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for PCAP export module."""

from __future__ import annotations

import struct
from pathlib import Path

from ipv8lab.address import IPv8Address
from ipv8lab.capture import CapturedPacket, PacketCapture
from ipv8lab.packet import IPv8Packet
from ipv8lab.pcap_export import (
    PCAP_MAGIC,
    DLT_USER0,
    PcapReader,
    PcapStats,
    PcapWriter,
    generate_lua_dissector,
    iv8cap_to_pcap,
    pcap_to_capture,
    save_lua_dissector,
    _PCAP_GLOBAL_FMT,
    _PCAP_GLOBAL_SIZE,
)


def _make_pkt(
    src: str = "64496.10.0.1.1",
    dst: str = "64497.10.0.1.100",
    payload: bytes = b"test",
) -> IPv8Packet:
    return IPv8Packet(
        src=IPv8Address.parse(src),
        dst=IPv8Address.parse(dst),
        payload=payload,
    )


# ---------------------------------------------------------------------------
# PcapWriter
# ---------------------------------------------------------------------------

class TestPcapWriter:
    def test_empty_writer(self) -> None:
        w = PcapWriter()
        assert w.packet_count == 0
        data = w.to_bytes()
        assert len(data) == _PCAP_GLOBAL_SIZE

    def test_global_header(self) -> None:
        w = PcapWriter()
        data = w.to_bytes()
        magic = struct.unpack_from("<I", data, 0)[0]
        assert magic == PCAP_MAGIC

    def test_add_packet(self) -> None:
        w = PcapWriter()
        w.add_packet(_make_pkt(), timestamp_ns=1_000_000_000)
        assert w.packet_count == 1

    def test_add_captured(self) -> None:
        cap = CapturedPacket(timestamp_ns=500, packet=_make_pkt())
        w = PcapWriter()
        w.add_captured(cap)
        assert w.packet_count == 1

    def test_add_capture(self) -> None:
        capture = PacketCapture()
        capture._packets = [
            CapturedPacket(timestamp_ns=0, packet=_make_pkt()),
            CapturedPacket(timestamp_ns=1000, packet=_make_pkt(payload=b"pkt2")),
        ]
        w = PcapWriter()
        w.add_capture(capture)
        assert w.packet_count == 2

    def test_roundtrip(self) -> None:
        pkt = _make_pkt(payload=b"roundtrip-data")
        w = PcapWriter()
        w.add_packet(pkt, timestamp_ns=2_500_000_000)

        data = w.to_bytes()
        reader = PcapReader(data)
        assert reader.packet_count == 1
        assert reader.packets[0].packet.payload == b"roundtrip-data"
        assert reader.packets[0].timestamp_ns == 2_500_000_000

    def test_multiple_packets(self) -> None:
        w = PcapWriter()
        for i in range(5):
            w.add_packet(_make_pkt(payload=f"pkt-{i}".encode()), timestamp_ns=i * 1_000_000)
        assert w.packet_count == 5
        data = w.to_bytes()
        reader = PcapReader(data)
        assert reader.packet_count == 5

    def test_save(self, tmp_path: Path) -> None:
        w = PcapWriter()
        w.add_packet(_make_pkt())
        stats = w.save(tmp_path / "test.pcap")
        assert isinstance(stats, PcapStats)
        assert stats.packets == 1
        assert stats.file_size > _PCAP_GLOBAL_SIZE
        assert (tmp_path / "test.pcap").exists()

    def test_clear(self) -> None:
        w = PcapWriter()
        w.add_packet(_make_pkt())
        w.clear()
        assert w.packet_count == 0

    def test_link_type(self) -> None:
        w = PcapWriter(link_type=200)
        data = w.to_bytes()
        _, _, _, _, _, _, link_type = struct.unpack(_PCAP_GLOBAL_FMT, data[:_PCAP_GLOBAL_SIZE])
        assert link_type == 200

    def test_timestamp_conversion(self) -> None:
        w = PcapWriter()
        # 1.5 seconds = 1 sec + 500000 usec
        w.add_packet(_make_pkt(), timestamp_ns=1_500_000_000)
        data = w.to_bytes()
        reader = PcapReader(data)
        # Should reconstruct to 1_500_000_000
        assert reader.packets[0].timestamp_ns == 1_500_000_000


# ---------------------------------------------------------------------------
# PcapReader
# ---------------------------------------------------------------------------

class TestPcapReader:
    def test_read_empty(self) -> None:
        w = PcapWriter()
        reader = PcapReader(w.to_bytes())
        assert reader.packet_count == 0
        assert reader.link_type == DLT_USER0

    def test_bad_magic(self) -> None:
        import pytest
        data = b"\x00" * 24
        with pytest.raises(ValueError, match="Bad PCAP magic"):
            PcapReader(data)

    def test_too_short(self) -> None:
        import pytest
        with pytest.raises(ValueError, match="too short"):
            PcapReader(b"\x00" * 10)

    def test_from_file(self, tmp_path: Path) -> None:
        w = PcapWriter()
        w.add_packet(_make_pkt(payload=b"fromfile"))
        w.save(tmp_path / "test.pcap")
        reader = PcapReader.from_file(tmp_path / "test.pcap")
        assert reader.packet_count == 1
        assert reader.packets[0].packet.payload == b"fromfile"

    def test_skips_malformed(self) -> None:
        # Build a pcap with valid header but garbled packet data
        w = PcapWriter()
        data = w.to_bytes()
        # Append a packet record with garbage data
        pkt_header = struct.pack("<IIII", 0, 0, 10, 10)
        garbage = b"\xff" * 10
        data += pkt_header + garbage
        reader = PcapReader(data)
        assert reader.packet_count == 0  # malformed skipped


# ---------------------------------------------------------------------------
# Conversion
# ---------------------------------------------------------------------------

class TestConversion:
    def test_iv8cap_to_pcap(self, tmp_path: Path) -> None:
        # Create an iv8cap file
        cap = PacketCapture()
        cap._packets = [
            CapturedPacket(timestamp_ns=0, packet=_make_pkt(payload=b"cap1")),
            CapturedPacket(timestamp_ns=1000, packet=_make_pkt(payload=b"cap2")),
        ]
        iv8cap_path = tmp_path / "test.iv8cap"
        cap.save(iv8cap_path)

        pcap_path = tmp_path / "test.pcap"
        stats = iv8cap_to_pcap(iv8cap_path, pcap_path)
        assert stats.packets == 2
        assert pcap_path.exists()

        # Verify readback
        reader = PcapReader.from_file(pcap_path)
        assert reader.packet_count == 2

    def test_pcap_to_capture(self, tmp_path: Path) -> None:
        w = PcapWriter()
        w.add_packet(_make_pkt(payload=b"p2c"), timestamp_ns=42_000)
        w.save(tmp_path / "test.pcap")

        capture = pcap_to_capture(tmp_path / "test.pcap")
        assert capture.count == 1
        assert capture.packets[0].packet.payload == b"p2c"


# ---------------------------------------------------------------------------
# Lua dissector
# ---------------------------------------------------------------------------

class TestLuaDissector:
    def test_generate(self) -> None:
        lua = generate_lua_dissector()
        assert "ipv8" in lua
        assert "Proto(" in lua
        assert "wtap_encap" in lua
        assert "147" in lua

    def test_save(self, tmp_path: Path) -> None:
        path = tmp_path / "ipv8_dissector.lua"
        save_lua_dissector(path)
        assert path.exists()
        content = path.read_text()
        assert "Proto(" in content
