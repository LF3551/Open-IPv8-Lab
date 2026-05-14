# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""IPv8 Packet Format per draft-thain-ipv8-00 Section 5.1.

Header layout (32 bytes):

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|         Total Length          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                  Source ASN Prefix (r.r.r.r)                  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                  Source Host Address (n.n.n.n)                |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |               Destination ASN Prefix (r.r.r.r)               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                Destination Host Address (n.n.n.n)             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Fields packed as: !BBHHHBBHIIII  (32 bytes)
  B  = version_ihl   (version << 4 | ihl)
  B  = tos
  H  = total_length
  H  = identification
  H  = flags_frag    (flags << 13 | frag_offset)
  B  = ttl
  B  = protocol
  H  = header_checksum
  I  = src_asn_prefix
  I  = src_host
  I  = dst_asn_prefix
  I  = dst_host
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from ipv8lab.address import IPv8Address
from ipv8lab.checksum import crc32_checksum
from ipv8lab.errors import ChecksumMismatchError, InvalidPacketError

# !BBHHHBBHIIII = 1+1+2+2+2+1+1+2+4+4+4+4 = 28... no.
# Let's count: B(1)+B(1)+H(2)+H(2)+H(2)+B(1)+B(1)+H(2)+I(4)+I(4)+I(4)+I(4) = 28
# But the spec says 32 bytes (IPv4 20 + 8 extra for 64-bit addresses).
# The difference: IPv4 has 2x32-bit addr = 8 bytes; IPv8 has 4x32-bit = 16 bytes.
# So IPv4(20) - 8(addrs) + 16(addrs) = 28. Wait, that's 28.
# Actually: IPv4 header minimum = 20 bytes with 2x 32-bit addresses.
#   IPv8 replaces each 32-bit address with 2x 32-bit (ASN+host) = 64-bit.
#   So 20 - 8 + 16 = 28 bytes. The spec says "8 octets longer" = 20+8 = 28.
# Our current header is also 28 bytes but with wrong field layout. Let's fix.

HEADER_FMT = "!BBHHHBBHIIII"
HEADER_SIZE = struct.calcsize(HEADER_FMT)  # 28 bytes

IPV8_VERSION = 8
IPV8_IHL = 7  # 28 / 4 = 7 (header length in 32-bit words)

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_EXPERIMENTAL = 253


@dataclass(slots=True)
class IPv8Packet:
    """IPv8 packet per draft-thain-ipv8-00 Section 5.1."""

    src: IPv8Address
    dst: IPv8Address
    payload: bytes = b""
    version: int = IPV8_VERSION
    ihl: int = IPV8_IHL
    tos: int = 0
    identification: int = 0
    flags: int = 0
    fragment_offset: int = 0
    ttl: int = 64
    protocol: int = PROTO_EXPERIMENTAL

    # computed on serialization
    _checksum: int = field(default=0, init=False, repr=False)

    def to_bytes(self) -> bytes:
        """Serialize the packet to bytes."""
        total_length = HEADER_SIZE + len(self.payload)
        version_ihl = (self.version << 4) | (self.ihl & 0x0F)
        flags_frag = ((self.flags & 0x07) << 13) | (self.fragment_offset & 0x1FFF)
        src_asn = (self.src.routing_prefix[0] << 24 | self.src.routing_prefix[1] << 16
                   | self.src.routing_prefix[2] << 8 | self.src.routing_prefix[3])
        src_host = (self.src.host_part[0] << 24 | self.src.host_part[1] << 16
                    | self.src.host_part[2] << 8 | self.src.host_part[3])
        dst_asn = (self.dst.routing_prefix[0] << 24 | self.dst.routing_prefix[1] << 16
                   | self.dst.routing_prefix[2] << 8 | self.dst.routing_prefix[3])
        dst_host = (self.dst.host_part[0] << 24 | self.dst.host_part[1] << 16
                    | self.dst.host_part[2] << 8 | self.dst.host_part[3])

        # Build header with checksum=0 to compute CRC
        header_no_cksum = struct.pack(
            HEADER_FMT,
            version_ihl, self.tos, total_length,
            self.identification, flags_frag,
            self.ttl, self.protocol, 0,
            src_asn, src_host, dst_asn, dst_host,
        )
        self._checksum = crc32_checksum(header_no_cksum + self.payload)

        header = struct.pack(
            HEADER_FMT,
            version_ihl, self.tos, total_length,
            self.identification, flags_frag,
            self.ttl, self.protocol, self._checksum & 0xFFFF,
            src_asn, src_host, dst_asn, dst_host,
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
            version_ihl, tos, total_length,
            identification, flags_frag,
            ttl, protocol, checksum,
            src_asn, src_host, dst_asn, dst_host,
        ) = struct.unpack(HEADER_FMT, data[:HEADER_SIZE])

        version = (version_ihl >> 4) & 0x0F
        ihl = version_ihl & 0x0F
        flags = (flags_frag >> 13) & 0x07
        fragment_offset = flags_frag & 0x1FFF

        payload_length = total_length - HEADER_SIZE
        if payload_length < 0:
            payload_length = 0

        expected_total = HEADER_SIZE + payload_length
        if len(data) < expected_total:
            raise InvalidPacketError(
                f"Packet truncated: have {len(data)} bytes, header says {expected_total}"
            )

        payload = data[HEADER_SIZE:HEADER_SIZE + payload_length]

        if verify:
            header_no_cksum = struct.pack(
                HEADER_FMT,
                version_ihl, tos, total_length,
                identification, flags_frag,
                ttl, protocol, 0,
                src_asn, src_host, dst_asn, dst_host,
            )
            expected = crc32_checksum(header_no_cksum + payload) & 0xFFFF
            if expected != checksum:
                raise ChecksumMismatchError("Packet checksum verification failed")

        def _u32_to_tuple(v: int) -> tuple[int, int, int, int]:
            return ((v >> 24) & 0xFF, (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF)

        pkt = cls(
            src=IPv8Address(routing_prefix=_u32_to_tuple(src_asn), host_part=_u32_to_tuple(src_host)),
            dst=IPv8Address(routing_prefix=_u32_to_tuple(dst_asn), host_part=_u32_to_tuple(dst_host)),
            payload=payload,
            version=version,
            ihl=ihl,
            tos=tos,
            identification=identification,
            flags=flags,
            fragment_offset=fragment_offset,
            ttl=ttl,
            protocol=protocol,
        )
        pkt._checksum = checksum
        return pkt

    @property
    def checksum(self) -> int:
        return self._checksum
