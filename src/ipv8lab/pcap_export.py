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
from enum import IntEnum
from pathlib import Path

from ipv8lab.capture import CapturedPacket, PacketCapture
from ipv8lab.packet import IPv8Packet

# --- PCAP constants ---

PCAP_MAGIC = 0xA1B2C3D4          # little-endian magic
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_SNAPLEN = 65535
DLT_USER0 = 147                  # user-defined link type
DLT_EN10MB = 1                   # Ethernet (used for ETH_P_IPV8 captures)

# EtherType values
ETH_P_IP    = 0x0800             # IPv4
ETH_P_IPV8  = 0x8080             # IPv8 native frames (spec §5.2)

# Fake source/destination MAC used when building synthetic Ethernet frames
_BCAST_MAC = b"\xff\xff\xff\xff\xff\xff"
_ZERO_MAC  = b"\x00\x00\x00\x00\x00\x00"

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


# ---------------------------------------------------------------------------
# Wire encapsulation selection (spec §5.2)
# ---------------------------------------------------------------------------

class WireEncap(IntEnum):
    """On-wire framing type for an IPv8 packet.

    Spec §5.2 rules:

    * **ETH_P_IP** (``0x0800``) — destination is reached at the segment's
      Primary RN.  Covers Primary↔Primary and all IPv4-only↔IPv4-only
      traffic.
    * **ETH_P_IPV8** (``0x8080``) — destination RN differs from the
      segment's Primary RN (cross-RN or peer's Secondary RN on the same
      segment).
    * **DLT_USER0** — lab-internal / pcap-only framing (no Ethernet
      header), for captures that don't represent real Ethernet frames.
    """

    ETH_P_IP    = ETH_P_IP
    ETH_P_IPV8  = ETH_P_IPV8
    DLT_USER0   = DLT_USER0


def select_encap(
    src_rn: int,
    dst_rn: int,
    segment_primary_rn: int,
) -> WireEncap:
    """Choose the correct wire encapsulation per spec §5.2.

    Returns :attr:`WireEncap.ETH_P_IPV8` when the destination RN differs
    from the segment Primary RN; :attr:`WireEncap.ETH_P_IP` otherwise.
    """
    if dst_rn != segment_primary_rn or src_rn != segment_primary_rn:
        return WireEncap.ETH_P_IPV8
    return WireEncap.ETH_P_IP


def _build_eth_frame(raw_ipv8: bytes, ethertype: int) -> bytes:
    """Wrap raw IPv8 bytes in a minimal Ethernet II frame."""
    eth_header = _ZERO_MAC + _BCAST_MAC + struct.pack("!H", ethertype)
    return eth_header + raw_ipv8


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
        encap: WireEncap = WireEncap.DLT_USER0,
    ) -> None:
        """Add a packet with a nanosecond timestamp.

        *encap* controls the on-wire framing:

        * ``DLT_USER0`` — raw IPv8 bytes only (default, backwards-compat).
        * ``ETH_P_IP`` or ``ETH_P_IPV8`` — wrap in an Ethernet II frame
          with the corresponding EtherType.  The writer's ``link_type``
          is automatically promoted to ``DLT_EN10MB`` on the first
          Ethernet-framed packet.
        """
        raw = packet.to_bytes()
        if encap in (WireEncap.ETH_P_IP, WireEncap.ETH_P_IPV8):
            raw = _build_eth_frame(raw, int(encap))
            if self._link_type == DLT_USER0:
                self._link_type = DLT_EN10MB
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

local ipv8 = Proto("ipv8", "IPv8 Protocol (draft-thain-ipv8)")

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
local f_src_rn    = ProtoField.uint32("ipv8.src_rn", "Source RN", base.DEC)
local f_src_la    = ProtoField.ipv4("ipv8.src_la", "Source LA")
local f_dst_rn    = ProtoField.uint32("ipv8.dst_rn", "Destination RN", base.DEC)
local f_dst_la    = ProtoField.ipv4("ipv8.dst_la", "Destination LA")
local f_payload   = ProtoField.bytes("ipv8.payload", "Payload")

ipv8.fields = {
    f_version, f_ihl, f_tos, f_total_len, f_ident,
    f_flags, f_frag, f_ttl, f_proto, f_checksum,
    f_src_rn, f_src_la, f_dst_rn, f_dst_la, f_payload
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

    local src_rn = buffer(12, 4):uint()
    local dst_rn = buffer(20, 4):uint()
    subtree:add(f_src_rn, buffer(12, 4))
    subtree:add(f_src_la, buffer(16, 4))
    subtree:add(f_dst_rn, buffer(20, 4))
    subtree:add(f_dst_la, buffer(24, 4))

    local total_len = buffer(2, 2):uint()
    local hdr_len = ihl * 4
    if total_len > hdr_len and buffer:len() > hdr_len then
        local payload_len = math.min(total_len - hdr_len, buffer:len() - hdr_len)
        subtree:add(f_payload, buffer(hdr_len, payload_len))
    end

    -- Info column
    pinfo.cols.info = string.format(
        "RN%d.%s → RN%d.%s",
        src_rn, tostring(buffer(16, 4):ipv4()),
        dst_rn, tostring(buffer(24, 4):ipv4())
    )
end

-- Register on EtherType 0x8080 (native IPv8 frames, spec §5.2)
local eth_table = DissectorTable.get("ethertype")
eth_table:add(0x8080, ipv8)

-- Also register for DLT_USER0 (147) for pcap captures without Ethernet header
local wtap = DissectorTable.get("wtap_encap")
wtap:add(147, ipv8)
'''


def generate_lua_dissector() -> str:
    """Return the Wireshark Lua dissector source code."""
    return _LUA_DISSECTOR


def save_lua_dissector(path: str | Path) -> None:
    """Write the Wireshark Lua dissector to a file."""
    Path(path).write_text(_LUA_DISSECTOR)
