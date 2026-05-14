# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""DNS A8 record type per draft-thain-ipv8-00 Section 7.

An A8 record carries a 64-bit IPv8 address in network byte order.
The nominal A8 response is an even/odd pair providing load balancing
and redundancy by default.

RFC 1918 addresses MUST NOT be published as A8 records in public DNS.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from ipv8lab.address import IPv8Address

# A8 record type (IANA assignment pending)
A8_RRTYPE = "A8"

# RFC 1918 private ranges in n.n.n.n
_RFC1918_RANGES: list[tuple[int, int]] = [
    (0x0A000000, 0x0AFFFFFF),  # 10.0.0.0/8
    (0xAC100000, 0xAC1FFFFF),  # 172.16.0.0/12
    (0xC0A80000, 0xC0A8FFFF),  # 192.168.0.0/16
]


def _is_rfc1918(host: int) -> bool:
    return any(lo <= host <= hi for lo, hi in _RFC1918_RANGES)


@dataclass(frozen=True, slots=True)
class A8Record:
    """A DNS A8 record."""

    name: str
    address: IPv8Address
    ttl: int = 3600

    def to_wire(self) -> bytes:
        """Serialize the address to 8 bytes (network byte order)."""
        return struct.pack("!Q", self.address.to_int())

    @classmethod
    def from_wire(cls, name: str, data: bytes, ttl: int = 3600) -> A8Record:
        """Deserialize an A8 record from 8 bytes."""
        if len(data) != 8:
            msg = f"A8 rdata must be 8 bytes, got {len(data)}"
            raise ValueError(msg)
        (value,) = struct.unpack("!Q", data)
        addr = IPv8Address.from_int(value)
        return cls(name=name, address=addr, ttl=ttl)


def is_even_odd_pair(a: IPv8Address, b: IPv8Address) -> bool:
    """Check if two addresses form a valid even/odd pair."""
    va = a.to_int()
    vb = b.to_int()
    if va > vb:
        va, vb = vb, va
    return va % 2 == 0 and vb == va + 1


def make_even_odd_pair(
    name: str,
    base: IPv8Address,
    ttl: int = 3600,
) -> tuple[A8Record, A8Record]:
    """Create an even/odd A8 record pair from a base address.

    The base address is adjusted to be even if needed.
    """
    val = base.to_int()
    even_val = val & ~1  # force even
    odd_val = even_val + 1
    even_addr = IPv8Address.from_int(even_val)
    odd_addr = IPv8Address.from_int(odd_val)
    return A8Record(name, even_addr, ttl), A8Record(name, odd_addr, ttl)


def validate_public_a8(record: A8Record) -> list[str]:
    """Validate an A8 record for public DNS publication.

    Returns a list of violation descriptions (empty = valid).
    """
    violations: list[str] = []
    hp = record.address.host_part
    host = (hp[0] << 24) | (hp[1] << 16) | (hp[2] << 8) | hp[3]
    if _is_rfc1918(host):
        violations.append(
            f"RFC 1918 address {record.address} MUST NOT be published in public DNS"
        )
    return violations


def format_zone_line(record: A8Record) -> str:
    """Format an A8 record as a DNS zone file line."""
    return f"{record.name}\t{record.ttl}\tIN\t{A8_RRTYPE}\t{record.address}"
