# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Address Usage Model per draft-thain-ipv8- Section 4.11.

Consolidated address space table mapping every r.r.r.r / n.n.n.n
combination to its usage category and external routing disposition.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from ipv8lab.address import IPv8Address


# ---------------------------------------------------------------------------
# External routing disposition
# ---------------------------------------------------------------------------

class ExternalRouting(str, Enum):
    NEVER = "never"
    PRIVATE = "private"
    GLOBAL = "global"
    IPV4_ONLY = "ipv4-only"


# ---------------------------------------------------------------------------
# Usage entry
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class UsageEntry:
    """One row of the Section 4.11 address usage table."""

    prefix_pattern: str
    usage: str
    external_routing: ExternalRouting
    note: str = ""


# ---------------------------------------------------------------------------
# The canonical table (Section 4.11)
# ---------------------------------------------------------------------------

ADDRESS_USAGE_TABLE: tuple[UsageEntry, ...] = (
    UsageEntry(
        prefix_pattern="127.x.x.x.n.n.n.n",
        usage="Internal devices (all zones)",
        external_routing=ExternalRouting.NEVER,
        note="Internal zone prefix — MUST NOT be routed externally",
    ),
    UsageEntry(
        prefix_pattern="127.127.0.0.n.n.n.n",
        usage="Inter-company interop DMZ",
        external_routing=ExternalRouting.PRIVATE,
        note="Shared XLATE8 DMZ between organisations",
    ),
    UsageEntry(
        prefix_pattern="100.x.x.x.n.n.n.n",
        usage="RINE peering links only",
        external_routing=ExternalRouting.NEVER,
        note="AS-to-AS peering at IXPs — MUST NOT be globally routed",
    ),
    UsageEntry(
        prefix_pattern="<asn>.222.x.x.x",
        usage="Interior router links",
        external_routing=ExternalRouting.NEVER,
        note="Router-to-router /31 links — RFC 1918 analogue",
    ),
    UsageEntry(
        prefix_pattern="0.0.255.254.n.n.n.n",
        usage="Private BGP8 peering",
        external_routing=ExternalRouting.PRIVATE,
        note="ASN 65534 — private inter-company BGP8 peering (RFC 6996)",
    ),
    UsageEntry(
        prefix_pattern="0.0.255.253.n.n.n.n",
        usage="Documentation and testing",
        external_routing=ExternalRouting.PRIVATE,
        note="ASN 65533 — reserved for documentation purposes",
    ),
    UsageEntry(
        prefix_pattern="<own-asn>.n.n.n.n",
        usage="Explicit public services only",
        external_routing=ExternalRouting.GLOBAL,
        note="Public ASN unicast — routed via eBGP8",
    ),
    UsageEntry(
        prefix_pattern="0.0.0.0.n.n.n.n",
        usage="IPv4 compatible (r.r.r.r = 0)",
        external_routing=ExternalRouting.IPV4_ONLY,
        note="Processed by standard IPv4 rules",
    ),
    UsageEntry(
        prefix_pattern="ff.ff.x.x.n.n.n.n",
        usage="Cross-ASN multicast",
        external_routing=ExternalRouting.GLOBAL,
        note="Cross-ASN multicast (ff.ff.00.00/16)",
    ),
    UsageEntry(
        prefix_pattern="ff.ff.ff.ff.n.n.n.n",
        usage="Broadcast",
        external_routing=ExternalRouting.NEVER,
        note="L2 broadcast — MUST NOT be routed",
    ),
)


# ---------------------------------------------------------------------------
# Classify an address
# ---------------------------------------------------------------------------

def classify_address(addr: IPv8Address) -> UsageEntry:
    """Classify *addr* according to the Section 4.11 usage model.

    Returns the most specific matching entry from the canonical table.
    """
    # Order matters — most specific first

    if addr.is_broadcast():
        return ADDRESS_USAGE_TABLE[9]  # broadcast

    if addr.is_multicast():
        return ADDRESS_USAGE_TABLE[8]  # cross-ASN multicast

    if addr.is_interop_prefix():
        return ADDRESS_USAGE_TABLE[1]  # 127.127.0.0 interop DMZ

    if addr.is_internal_zone():
        return ADDRESS_USAGE_TABLE[0]  # 127.x.x.x internal

    if addr.is_rine_prefix():
        return ADDRESS_USAGE_TABLE[2]  # 100.x.x.x RINE

    if addr.is_interior_link():
        return ADDRESS_USAGE_TABLE[3]  # 222.x.x.x interior link

    if addr.is_private_peering_asn():
        return ADDRESS_USAGE_TABLE[4]  # ASN 65534

    if addr.is_documentation_asn():
        return ADDRESS_USAGE_TABLE[5]  # ASN 65533

    if addr.is_ipv4_compatible():
        return ADDRESS_USAGE_TABLE[7]  # 0.0.0.0 IPv4

    return ADDRESS_USAGE_TABLE[6]  # ASN unicast (global)


# ---------------------------------------------------------------------------
# Human-readable summary
# ---------------------------------------------------------------------------

def usage_summary(addr: IPv8Address) -> dict[str, str]:
    """Return a dict summary of the address usage classification."""
    entry = classify_address(addr)
    return {
        "address": addr.full_notation,
        "pattern": entry.prefix_pattern,
        "usage": entry.usage,
        "external_routing": entry.external_routing.value,
        "note": entry.note,
    }
