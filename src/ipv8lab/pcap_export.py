# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""PCAP export for Wireshark integration.

Exports IPv8 Lab packet captures to standard PCAP format (libpcap)
that can be opened in Wireshark, tcpdump, or any pcap-compatible tool.

Format: classic pcap (little-endian)
  - Global header: magic, version 2.4, link type DLT_USER0 (147)
  - Per-packet: timestamp, captured/original length, raw packet bytes

DLT_USER0 (147) is reserved for user-defined link-layer types.
Wireshark can decode these via a Lua dissector (included as
`ipv8_dissector.lua`).

Also supports:
  - .iv8cap → .pcap conversion
  - PacketCapture → pcap bytes
  - Wireshark Lua dissector generation
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

from ipv8lab.capture import CapturedPacket, PacketCapture
from ipv8lab.packet import IPv8Packet

# --- PCAP constants ---

PCAP_MAGIC = 0xA1B2C3D4          # little-endian magic
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_SNAPLEN = 65535
DLT_USER0 = 147                  # user-defined link type

# Global header: magic(4) + ver_major(2) + ver_minor(2) + thiszone(4) +
#                sigfigs(4) + snaplen(4) + linktype(4) = 24 bytes
_PCAP_GLOBAL_FMT = "<IHHiIII"
_PCAP_GLOBAL_SIZE = struct.calcsize(_PCAP_GLOBAL_FMT)  # 24

# Per-packet header: ts_sec(4) + ts_usec(4) + incl_len(4) + orig_len(4) = 16
_PCAP_PKT_FMT = "<IIII"
_PCAP_PKT_SIZE = struct.calcsize(_PCAP_PKT_FMT)  # 16


def _build_global_header(link_type: int = DLT_USER0) -> bytes:
    """Build a pcap global header."""
    return struct.pack(
        _PCAP_GLOBAL_FMT,
        PCAP_MAGIC,
        PCAP_VERSION_MAJOR,
        PCAP_VERSION_MINOR,
        0,               # thiszone (GMT)
        0,               # sigfigs
        PCAP_SNAPLEN,
        link_type,
    )


def _build_packet_record(
    ts_sec: int,
    ts_usec: int,
    raw: bytes,
    snaplen: int = PCAP_SNAPLEN,
) -> bytes:
    """Build a pcap packet record (header + data)."""
    captured = min(len(raw), snaplen)
    pkt_header = struct.pack(
        _PCAP_PKT_FMT,
        ts_sec,
        ts_usec,
        captured,     # included length
        len(raw),     # original length
    )
    return pkt_header + raw[:captured]


# ---------------------------------------------------------------------------
# PCAP writer
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PcapStats:
    """Statistics from a PCAP export."""

    packets: int
    bytes_total: int
    file_size: int


class PcapWriter:
    """Writes IPv8 packets to PCAP format."""

    def __init__(self, link_type: int = DLT_USER0) -> None:
        self._link_type = link_type
        self._records: list[tuple[int, int, bytes]] = []  # (ts_sec, ts_usec, raw)

    @property
    def packet_count(self) -> int:
        return len(self._records)

    def add_packet(
        self,
        packet: IPv8Packet,
        timestamp_ns: int = 0,
    ) -> None:
        """Add a packet with a nanosecond timestamp."""
        raw = packet.to_bytes()
        ts_sec = timestamp_ns // 1_000_000_000
        ts_usec = (timestamp_ns % 1_000_000_000) // 1_000
        self._records.append((ts_sec, ts_usec, raw))

    def add_captured(self, captured: CapturedPacket) -> None:
        """Add a CapturedPacket (from PacketCapture)."""
        self.add_packet(captured.packet, captured.timestamp_ns)

    def add_capture(self, capture: PacketCapture) -> None:
        """Add all packets from a PacketCapture."""
        for cap in capture.packets:
            self.add_captured(cap)

    def to_bytes(self) -> bytes:
        """Serialize the full PCAP file to bytes."""
        parts = [_build_global_header(self._link_type)]
        for ts_sec, ts_usec, raw in self._records:
            parts.append(_build_packet_record(ts_sec, ts_usec, raw))
        return b"".join(parts)

    def save(self, path: str | Path) -> PcapStats:
        """Write the PCAP file to disk."""
        data = self.to_bytes()
        Path(path).write_bytes(data)
        total_payload = sum(len(raw) for _, _, raw in self._records)
        return PcapStats(
            packets=len(self._records),
            bytes_total=total_payload,
            file_size=len(data),
        )

    def clear(self) -> None:
        self._records.clear()


# ---------------------------------------------------------------------------
# PCAP reader
# ---------------------------------------------------------------------------


class PcapReader:
    """Reads pcap files and extracts IPv8 packets."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._link_type = 0
        self._packets: list[CapturedPacket] = []
        self._parse()

    def _parse(self) -> None:
        if len(self._data) < _PCAP_GLOBAL_SIZE:
            msg = f"PCAP too short: {len(self._data)} bytes"
            raise ValueError(msg)

        magic, ver_major, ver_minor, _, _, snaplen, link_type = struct.unpack(
            _PCAP_GLOBAL_FMT, self._data[:_PCAP_GLOBAL_SIZE],
        )
        if magic != PCAP_MAGIC:
            msg = f"Bad PCAP magic: 0x{magic:08X}"
            raise ValueError(msg)

        self._link_type = link_type
        offset = _PCAP_GLOBAL_SIZE

        while offset + _PCAP_PKT_SIZE <= len(self._data):
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
                _PCAP_PKT_FMT, self._data[offset:offset + _PCAP_PKT_SIZE],
            )
            offset += _PCAP_PKT_SIZE

            if offset + incl_len > len(self._data):
                break

            raw = self._data[offset:offset + incl_len]
            offset += incl_len

            timestamp_ns = ts_sec * 1_000_000_000 + ts_usec * 1_000
            try:
                pkt = IPv8Packet.from_bytes(raw)
                self._packets.append(CapturedPacket(timestamp_ns=timestamp_ns, packet=pkt))
            except Exception:  # noqa: BLE001
                # Skip non-IPv8 or malformed packets
                continue

    @property
    def link_type(self) -> int:
        return self._link_type

    @property
    def packets(self) -> list[CapturedPacket]:
        return list(self._packets)

    @property
    def packet_count(self) -> int:
        return len(self._packets)

    @classmethod
    def from_file(cls, path: str | Path) -> "PcapReader":
        """Load a PCAP file from disk."""
        data = Path(path).read_bytes()
        return cls(data)


# ---------------------------------------------------------------------------
# Conversion helpers
# ---------------------------------------------------------------------------


def iv8cap_to_pcap(iv8cap_path: str | Path, pcap_path: str | Path) -> PcapStats:
    """Convert an .iv8cap file to .pcap format."""
    capture = PacketCapture.load(iv8cap_path)
    writer = PcapWriter()
    writer.add_capture(capture)
    return writer.save(pcap_path)


def pcap_to_capture(pcap_path: str | Path) -> PacketCapture:
    """Convert a .pcap file to a PacketCapture object."""
    reader = PcapReader.from_file(pcap_path)
    capture = PacketCapture()
    capture._packets = list(reader.packets)
    return capture


# ---------------------------------------------------------------------------
# Wireshark Lua dissector
# ---------------------------------------------------------------------------

_LUA_DISSECTOR = '''\
-- IPv8 Lab Wireshark dissector
-- Place in ~/.local/lib/wireshark/plugins/ (Linux)
-- or ~/Library/Application Support/Wireshark/plugins/ (macOS)
-- or %APPDATA%\\Wireshark\\plugins\\ (Windows)

local ipv8 = Proto("ipv8", "IPv8 Protocol (draft-thain-ipv8-00)")

-- Header fields
local f_version   = ProtoField.uint8("ipv8.version", "Version", base.DEC, nil, 0xF0)
local f_ihl       = ProtoField.uint8("ipv8.ihl", "IHL (32-bit words)", base.DEC, nil, 0x0F)
local f_tos       = ProtoField.uint8("ipv8.tos", "Type of Service", base.HEX)
local f_total_len = ProtoField.uint16("ipv8.total_length", "Total Length", base.DEC)
local f_ident     = ProtoField.uint16("ipv8.identification", "Identification", base.HEX)
local f_flags     = ProtoField.uint16("ipv8.flags", "Flags", base.HEX, nil, 0xE000)
local f_frag      = ProtoField.uint16("ipv8.frag_offset", "Fragment Offset", base.DEC, nil, 0x1FFF)
local f_ttl       = ProtoField.uint8("ipv8.ttl", "Time to Live", base.DEC)
local f_proto     = ProtoField.uint8("ipv8.protocol", "Protocol", base.DEC)
local f_checksum  = ProtoField.uint16("ipv8.checksum", "Header Checksum", base.HEX)
local f_src_asn   = ProtoField.uint32("ipv8.src_asn", "Source ASN Prefix", base.DEC)
local f_src_host  = ProtoField.ipv4("ipv8.src_host", "Source Host")
local f_dst_asn   = ProtoField.uint32("ipv8.dst_asn", "Destination ASN Prefix", base.DEC)
local f_dst_host  = ProtoField.ipv4("ipv8.dst_host", "Destination Host")
local f_payload   = ProtoField.bytes("ipv8.payload", "Payload")

ipv8.fields = {
    f_version, f_ihl, f_tos, f_total_len, f_ident,
    f_flags, f_frag, f_ttl, f_proto, f_checksum,
    f_src_asn, f_src_host, f_dst_asn, f_dst_host, f_payload
}

function ipv8.dissector(buffer, pinfo, tree)
    if buffer:len() < 28 then return end

    pinfo.cols.protocol = "IPv8"

    local subtree = tree:add(ipv8, buffer(), "IPv8 Protocol")

    local ver_ihl = buffer(0, 1):uint()
    local version = bit.rshift(ver_ihl, 4)
    local ihl = bit.band(ver_ihl, 0x0F)

    subtree:add(f_version, buffer(0, 1))
    subtree:add(f_ihl, buffer(0, 1))
    subtree:add(f_tos, buffer(1, 1))
    subtree:add(f_total_len, buffer(2, 2))
    subtree:add(f_ident, buffer(4, 2))
    subtree:add(f_flags, buffer(6, 2))
    subtree:add(f_frag, buffer(6, 2))
    subtree:add(f_ttl, buffer(8, 1))
    subtree:add(f_proto, buffer(9, 1))
    subtree:add(f_checksum, buffer(10, 2))

    local src_asn = buffer(12, 4):uint()
    local dst_asn = buffer(20, 4):uint()
    subtree:add(f_src_asn, buffer(12, 4))
    subtree:add(f_src_host, buffer(16, 4))
    subtree:add(f_dst_asn, buffer(20, 4))
    subtree:add(f_dst_host, buffer(24, 4))

    local total_len = buffer(2, 2):uint()
    local hdr_len = ihl * 4
    if total_len > hdr_len and buffer:len() > hdr_len then
        local payload_len = math.min(total_len - hdr_len, buffer:len() - hdr_len)
        subtree:add(f_payload, buffer(hdr_len, payload_len))
    end

    -- Info column
    pinfo.cols.info = string.format(
        "AS%d.%s → AS%d.%s",
        src_asn, tostring(buffer(16, 4):ipv4()),
        dst_asn, tostring(buffer(24, 4):ipv4())
    )
end

-- Register for DLT_USER0 (147)
local wtap = DissectorTable.get("wtap_encap")
wtap:add(147, ipv8)
'''


def generate_lua_dissector() -> str:
    """Return the Wireshark Lua dissector source code."""
    return _LUA_DISSECTOR


def save_lua_dissector(path: str | Path) -> None:
    """Write the Wireshark Lua dissector to a file."""
    Path(path).write_text(_LUA_DISSECTOR)
