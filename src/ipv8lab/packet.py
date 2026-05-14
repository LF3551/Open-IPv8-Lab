# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""IPv8 Lab Packet Format — experimental packet builder and parser.

This is an internal format for educational purposes, **not** an official
IPv8 wire format.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from ipv8lab.address import IPv8Address
from ipv8lab.checksum import crc32_checksum, verify_checksum
from ipv8lab.errors import ChecksumMismatchError, InvalidPacketError

HEADER_FMT = "!BBBB QQ I I"
HEADER_SIZE = struct.calcsize(HEADER_FMT)  # 28 bytes

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_EXPERIMENTAL = 253


@dataclass(slots=True)
class IPv8Packet:
    """Experimental IPv8 Lab packet."""

    src: IPv8Address
    dst: IPv8Address
    payload: bytes = b""
    version: int = 1
    ttl: int = 64
    protocol: int = PROTO_EXPERIMENTAL
    flags: int = 0

    # computed on serialization
    _checksum: int = field(default=0, init=False, repr=False)

    def to_bytes(self) -> bytes:
        """Serialize the packet to bytes."""
        payload_length = len(self.payload)
        # Build header with checksum=0 to compute the real checksum
        header_no_cksum = struct.pack(
            HEADER_FMT,
            self.version,
            self.ttl,
            self.protocol,
            self.flags,
            self.src.to_int(),
            self.dst.to_int(),
            payload_length,
            0,
        )
        self._checksum = crc32_checksum(header_no_cksum + self.payload)
        header = struct.pack(
            HEADER_FMT,
            self.version,
            self.ttl,
            self.protocol,
            self.flags,
            self.src.to_int(),
            self.dst.to_int(),
            payload_length,
            self._checksum,
        )
        return header + self.payload

    @classmethod
    def from_bytes(cls, data: bytes, *, verify: bool = True) -> "IPv8Packet":
        """Deserialize a packet from bytes."""
        if len(data) < HEADER_SIZE:
            raise InvalidPacketError(
                f"Packet too short: {len(data)} bytes, need at least {HEADER_SIZE}"
            )
        (
            version,
            ttl,
            protocol,
            flags,
            src_int,
            dst_int,
            payload_length,
            checksum,
        ) = struct.unpack(HEADER_FMT, data[:HEADER_SIZE])

        expected_total = HEADER_SIZE + payload_length
        if len(data) < expected_total:
            raise InvalidPacketError(
                f"Packet truncated: have {len(data)} bytes, header says {expected_total}"
            )

        payload = data[HEADER_SIZE : HEADER_SIZE + payload_length]

        if verify:
            header_no_cksum = struct.pack(
                HEADER_FMT,
                version,
                ttl,
                protocol,
                flags,
                src_int,
                dst_int,
                payload_length,
                0,
            )
            if not verify_checksum(header_no_cksum + payload, checksum):
                raise ChecksumMismatchError("Packet checksum verification failed")

        pkt = cls(
            src=IPv8Address.from_int(src_int),
            dst=IPv8Address.from_int(dst_int),
            payload=payload,
            version=version,
            ttl=ttl,
            protocol=protocol,
            flags=flags,
        )
        pkt._checksum = checksum
        return pkt

    @property
    def checksum(self) -> int:
        return self._checksum
