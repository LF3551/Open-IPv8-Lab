# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""DNS A8 record type per draft-thain-ipv8- Section 7.

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


# ---------------------------------------------------------------------------
# ZS resource record (spec §3.4)
# ---------------------------------------------------------------------------

# ZS record type (private-use until IANA assignment)
ZS_RRTYPE = "ZS"


@dataclass(frozen=True, slots=True)
class ZSRecord:
    """A DNS ZS record — Zone Server pointer.

    MX-style: lower *preference* wins.  *target* is the FQDN of a
    Zone Server.  Multiple ZS records per owner name form a preference
    set; the resolver picks the lowest-preference reachable target.
    """

    name: str               # owner name, e.g. "64496.asn.arpa."
    preference: int         # lower = higher priority (like MX)
    target: str             # Zone Server FQDN
    ttl: int = 3600

    def to_wire(self) -> bytes:
        """Serialize as 2-byte preference + null-terminated target ASCII."""
        return struct.pack("!H", self.preference) + self.target.encode() + b"\x00"

    @classmethod
    def from_wire(cls, name: str, data: bytes, ttl: int = 3600) -> "ZSRecord":
        if len(data) < 3:  # noqa: PLR2004
            msg = "ZS rdata too short"
            raise ValueError(msg)
        (pref,) = struct.unpack("!H", data[:2])
        target = data[2:].rstrip(b"\x00").decode()
        return cls(name=name, preference=pref, target=target, ttl=ttl)


def format_zs_zone_line(record: ZSRecord) -> str:
    """Format a ZS record as a DNS zone file line."""
    return f"{record.name}\t{record.ttl}\tIN\t{ZS_RRTYPE}\t{record.preference} {record.target}"


# ---------------------------------------------------------------------------
# Zone Server discovery (spec §3.4 lookup order)
# ---------------------------------------------------------------------------

def _asn_arpa(rn: int) -> str:
    """Return the primary lookup name: ``<RN>.asn.arpa.``"""
    return f"{rn}.asn.arpa."


def _asn_openipv8(rn: int) -> str:
    """Return the secondary lookup name: ``<RN>.asn.openipv8.org.``"""
    return f"{rn}.asn.openipv8.org."


def _anycast_arpa(rn: int) -> str:
    """Return the anycast fallback name: ``anycast.<RN>.asn.arpa.``"""
    return f"anycast.{rn}.asn.arpa."


@dataclass
class ZSLookupResult:
    """Result of a Zone Server discovery lookup."""

    rn: int
    targets: list[str]          # ordered by preference (best first)
    source: str                 # "asn.arpa" | "openipv8.org" | "anycast" | "none"
    records_used: list[ZSRecord | A8Record]


class ZSResolver:
    """Mock Zone Server resolver implementing spec §3.4 lookup order.

    Maintains three in-memory record sets:
    1. ZS RRset under ``<RN>.asn.arpa.`` — primary (preferred)
    2. ZS RRset under ``<RN>.asn.openipv8.org.`` — secondary
    3. A record under ``anycast.<RN>.asn.arpa.`` — fallback

    Call :meth:`lookup` to perform the full 3-step resolution for an RN.
    """

    def __init__(self) -> None:
        self._zs: dict[str, list[ZSRecord]] = {}   # owner → sorted ZS records
        self._a8: dict[str, A8Record] = {}          # owner → A8 record

    # ----------------------------------------------------------------
    # Record installation
    # ----------------------------------------------------------------

    def add_zs(self, record: ZSRecord) -> None:
        """Add a ZS record.  Multiple records per owner are allowed."""
        self._zs.setdefault(record.name, []).append(record)
        self._zs[record.name].sort(key=lambda r: r.preference)

    def add_a8(self, record: A8Record) -> None:
        """Add an A8 record (used for anycast fallback)."""
        self._a8[record.name] = record

    # ----------------------------------------------------------------
    # Lookup
    # ----------------------------------------------------------------

    def lookup(self, rn: int) -> ZSLookupResult:
        """Perform the §3.4 lookup sequence for *rn*.

        Step 1 — ZS RRset under ``<RN>.asn.arpa.`` (MX-style sort).
        Step 2 — ZS RRset under ``<RN>.asn.openipv8.org.``.
        Step 3 — Anycast A8 record at ``anycast.<RN>.asn.arpa.``.
        """
        # Step 1: primary
        primary = self._zs.get(_asn_arpa(rn), [])
        if primary:
            return ZSLookupResult(
                rn=rn,
                targets=[r.target for r in primary],
                source="asn.arpa",
                records_used=list(primary),
            )

        # Step 2: secondary
        secondary = self._zs.get(_asn_openipv8(rn), [])
        if secondary:
            return ZSLookupResult(
                rn=rn,
                targets=[r.target for r in secondary],
                source="openipv8.org",
                records_used=list(secondary),
            )

        # Step 3: anycast fallback
        anycast = self._a8.get(_anycast_arpa(rn))
        if anycast:
            return ZSLookupResult(
                rn=rn,
                targets=[str(anycast.address)],
                source="anycast",
                records_used=[anycast],
            )

        return ZSLookupResult(rn=rn, targets=[], source="none", records_used=[])

    @property
    def zs_count(self) -> int:
        return sum(len(v) for v in self._zs.values())

    @property
    def a8_count(self) -> int:
        return len(self._a8)
