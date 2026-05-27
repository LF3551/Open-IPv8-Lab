# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Interior Link Convention per draft-thain-ipv8- Section 4.10.

The n.n.n.n range 222.0.0.0/8 is the well-known IPv8 interior link
address convention.  Every AS MAY use <own-asn>.222.x.x.x for
router-to-router interior link addressing within their AS.

Analogous to RFC 1918 — universally recognised, universally filtered,
never routed externally, never an endpoint.
"""

from __future__ import annotations

from dataclasses import dataclass

from ipv8lab.address import IPv8Address, asn_to_prefix_str


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

INTERIOR_LINK_PREFIX = 222
"""First octet of n.n.n.n reserved for interior links."""


# ---------------------------------------------------------------------------
# Point-to-point link pair
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class InteriorLinkPair:
    """A /31 point-to-point link between two routers."""

    asn: int
    link_id: int
    side_a: IPv8Address
    side_b: IPv8Address
    label: str = ""

    @property
    def asn_prefix(self) -> str:
        return asn_to_prefix_str(self.asn)


# ---------------------------------------------------------------------------
# Address generator
# ---------------------------------------------------------------------------

def make_interior_link(asn: int, link_id: int, *, label: str = "") -> InteriorLinkPair:
    """Generate a /31 interior link pair for *asn*.

    ``link_id`` selects which link (0-based).  Each link uses two
    consecutive addresses in 222.<link_hi>.<link_lo>.0-1.
    """
    link_hi = (link_id >> 8) & 0xFF
    link_lo = link_id & 0xFF
    prefix_str = asn_to_prefix_str(asn)

    addr_a = IPv8Address.parse(f"{prefix_str}.{INTERIOR_LINK_PREFIX}.{link_hi}.{link_lo}.0")
    addr_b = IPv8Address.parse(f"{prefix_str}.{INTERIOR_LINK_PREFIX}.{link_hi}.{link_lo}.1")

    return InteriorLinkPair(
        asn=asn,
        link_id=link_id,
        side_a=addr_a,
        side_b=addr_b,
        label=label,
    )


def make_interior_links(asn: int, count: int) -> list[InteriorLinkPair]:
    """Generate *count* sequential interior link pairs for *asn*."""
    return [make_interior_link(asn, i, label=f"link-{i}") for i in range(count)]


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def is_interior_link_address(addr: IPv8Address) -> bool:
    """Check if *addr* follows the interior link convention (222.x.x.x host)."""
    return addr.host_part[0] == INTERIOR_LINK_PREFIX


def validate_interior_link(addr: IPv8Address) -> list[str]:
    """Validate an interior link address.  Returns violations (empty = OK)."""
    violations: list[str] = []

    if not is_interior_link_address(addr):
        violations.append(
            f"{addr.full_notation}: host part does not start with "
            f"{INTERIOR_LINK_PREFIX} (222.x.x.x)"
        )
        return violations

    if addr.is_ipv4_compatible():
        violations.append(
            f"{addr.full_notation}: interior link with r.r.r.r=0.0.0.0 "
            "has no owning ASN — use <own-asn>.222.x.x.x"
        )

    if addr.is_internal_zone():
        violations.append(
            f"{addr.full_notation}: interior link MUST NOT use "
            "internal zone prefix (127.x.x.x)"
        )

    return violations


def check_interior_link_egress(addr: IPv8Address) -> str | None:
    """Return a violation string if an interior link address appears at egress."""
    if is_interior_link_address(addr):
        return (
            f"{addr.full_notation}: interior link (222.x.x.x) "
            "MUST NOT be routed externally (Section 4.10)"
        )
    return None


# ---------------------------------------------------------------------------
# Summary / inventory
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class InteriorLinkSummary:
    """Summary of interior link address space for an ASN."""

    asn: int
    asn_prefix: str
    address_range: str
    max_links: int
    convention: str


def summarize_interior_links(asn: int) -> InteriorLinkSummary:
    """Return a summary of the interior link space for *asn*."""
    prefix = asn_to_prefix_str(asn)
    return InteriorLinkSummary(
        asn=asn,
        asn_prefix=prefix,
        address_range=f"{prefix}.222.0.0.0 – {prefix}.222.255.255.255",
        max_links=8_388_608,  # 2^23 / 2 (pairs)
        convention="<own-asn>.222.x.x.x — RFC 1918 analogue, never routed externally",
    )
