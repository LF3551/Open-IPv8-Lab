# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""8to4 tunnelling per draft-thain-ipv8- Section 13.3.

Encapsulates IPv8 packets inside IPv4-compatible frames for transit
across IPv4-only networks.

Tunnel frame format:
  Magic (4 bytes): "8TO4"
  Flags (1 byte):  bit 0 = encrypted
  Reserved (1 byte)
  Payload length (2 bytes, big-endian)
  Payload (N bytes): full IPv8 packet
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from ipv8lab.packet import IPv8Packet

_MAGIC = b"8TO4"
_HEADER_FMT = "!4sBBH"
_HEADER_SIZE = struct.calcsize(_HEADER_FMT)  # 8 bytes

FLAG_ENCRYPTED = 0x01


@dataclass(frozen=True, slots=True)
class TunnelEndpoint:
    """An 8to4 tunnel endpoint (IPv4 address + port)."""

    ipv4_address: str
    port: int = 8418  # default 8to4 port


@dataclass(frozen=True, slots=True)
class TunnelFrame:
    """An encapsulated 8to4 frame."""

    packet: IPv8Packet
    encrypted: bool = False
    src_endpoint: TunnelEndpoint | None = None
    dst_endpoint: TunnelEndpoint | None = None


def encapsulate(packet: IPv8Packet, *, encrypted: bool = False) -> bytes:
    """Wrap an IPv8 packet in an 8to4 tunnel frame."""
    ipv8_bytes = packet.to_bytes()
    flags = FLAG_ENCRYPTED if encrypted else 0
    header = struct.pack(_HEADER_FMT, _MAGIC, flags, 0, len(ipv8_bytes))
    return header + ipv8_bytes


def decapsulate(data: bytes, *, verify_packet: bool = True) -> TunnelFrame:
    """Extract an IPv8 packet from an 8to4 tunnel frame."""
    if len(data) < _HEADER_SIZE:
        msg = f"8to4 frame too short: {len(data)} bytes, need {_HEADER_SIZE}"
        raise ValueError(msg)

    magic, flags, _reserved, payload_len = struct.unpack(
        _HEADER_FMT, data[:_HEADER_SIZE]
    )

    if magic != _MAGIC:
        msg = f"Invalid 8to4 magic: {magic!r}, expected {_MAGIC!r}"
        raise ValueError(msg)

    expected = _HEADER_SIZE + payload_len
    if len(data) < expected:
        msg = f"8to4 frame truncated: have {len(data)}, need {expected}"
        raise ValueError(msg)

    payload = data[_HEADER_SIZE:_HEADER_SIZE + payload_len]
    packet = IPv8Packet.from_bytes(payload, verify=verify_packet)
    encrypted = bool(flags & FLAG_ENCRYPTED)

    return TunnelFrame(packet=packet, encrypted=encrypted)


def is_8to4_frame(data: bytes) -> bool:
    """Check if data starts with the 8to4 magic."""
    return len(data) >= 4 and data[:4] == _MAGIC
