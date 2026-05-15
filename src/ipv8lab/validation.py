# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""IPv8 prefix validation rules per draft-thain-ipv8-02.

Implements routing-scope validation for reserved prefix ranges:
- 127.x.x.x  Internal Zone (Section 3.5) — MUST NOT be routed externally
- 100.x.x.x  RINE Peering (Section 3.9) — MUST NOT be globally routed
- 222.0.0.0/8 Interior Link (Section 3.10) — MUST NOT be routed externally
- ff.ff.ff.ff Broadcast (Section 12) — MUST NOT be routed
- Reserved ASNs 2130706432-2147483647 — MUST NOT be allocated (Section 3.5)
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from ipv8lab.address import IPv8Address


class RoutingScope(str, Enum):
    """Where an address is permitted to be routed."""

    GLOBAL = "global"
    INTERNAL = "internal"
    PRIVATE = "private"
    PEERING = "peering"
    LOCAL_ONLY = "local-only"
    NOT_ROUTABLE = "not-routable"


@dataclass(frozen=True, slots=True)
class PrefixValidation:
    """Result of prefix validation."""

    address: IPv8Address
    scope: RoutingScope
    routable_externally: bool
    violations: tuple[str, ...]


# ASN range reserved for internal zone use (Section 3.5)
_INTERNAL_ZONE_ASN_MIN = 2_130_706_432  # 127.0.0.0 as 32-bit int
_INTERNAL_ZONE_ASN_MAX = 2_147_483_647  # 127.255.255.255 as 32-bit int

# RINE peering ASN range (Section 3.9)
_RINE_ASN_MIN = 1_677_721_600  # 100.0.0.0
_RINE_ASN_MAX = 1_694_498_815  # 100.255.255.255

# Private Interop ASN (Section 4.8)
PRIVATE_PEERING_ASN = 65534   # Private inter-company BGP8 peering
DOCUMENTATION_ASN = 65533     # Documentation and testing


def validate_prefix(addr: IPv8Address) -> PrefixValidation:
    """Validate an address against prefix rules and determine routing scope."""

    # Broadcast
    if addr.is_broadcast():
        return PrefixValidation(
            address=addr,
            scope=RoutingScope.NOT_ROUTABLE,
            routable_externally=False,
            violations=(),
        )

    # Cross-ASN multicast
    if addr.is_multicast():
        return PrefixValidation(
            address=addr,
            scope=RoutingScope.GLOBAL,
            routable_externally=True,
            violations=(),
        )

    # Internal zone — 127.x.x.x
    if addr.is_internal_zone():
        return PrefixValidation(
            address=addr,
            scope=RoutingScope.INTERNAL,
            routable_externally=False,
            violations=(),
        )

    # Private inter-company peering — ASN 65534 (Section 4.8)
    if addr.is_private_peering_asn():
        return PrefixValidation(
            address=addr,
            scope=RoutingScope.PRIVATE,
            routable_externally=False,
            violations=(),
        )

    # Documentation/testing — ASN 65533 (Section 4.8)
    if addr.is_documentation_asn():
        return PrefixValidation(
            address=addr,
            scope=RoutingScope.PRIVATE,
            routable_externally=False,
            violations=(),
        )

    # RINE peering — 100.x.x.x
    if addr.is_rine_prefix():
        return PrefixValidation(
            address=addr,
            scope=RoutingScope.PEERING,
            routable_externally=False,
            violations=(),
        )

    # Interior link convention — n.n.n.n in 222.0.0.0/8
    if addr.is_interior_link():
        return PrefixValidation(
            address=addr,
            scope=RoutingScope.INTERNAL,
            routable_externally=False,
            violations=(),
        )

    # Intra-ASN multicast
    if addr.is_intra_asn_multicast():
        return PrefixValidation(
            address=addr,
            scope=RoutingScope.LOCAL_ONLY,
            routable_externally=False,
            violations=(),
        )

    # IPv4 compatible
    if addr.is_ipv4_compatible():
        return PrefixValidation(
            address=addr,
            scope=RoutingScope.GLOBAL,
            routable_externally=True,
            violations=(),
        )

    # ASN unicast — global
    return PrefixValidation(
        address=addr,
        scope=RoutingScope.GLOBAL,
        routable_externally=True,
        violations=(),
    )


def check_egress(src: IPv8Address, dst: IPv8Address) -> list[str]:
    """Check if a packet from src→dst would violate egress rules (Section 18).

    Returns a list of violation descriptions. Empty list = OK.
    """
    violations: list[str] = []

    # Internal zone MUST NOT appear on WAN (Section 18.2)
    if src.is_internal_zone():
        violations.append(
            f"Source {src.full_notation}: internal zone prefix (127.x.x.x) "
            "MUST NOT appear on external interfaces"
        )
    if dst.is_internal_zone():
        violations.append(
            f"Destination {dst.full_notation}: internal zone prefix (127.x.x.x) "
            "MUST NOT be routed externally"
        )

    # RINE MUST NOT appear in eBGP8 (Section 18.3)
    if src.is_rine_prefix():
        violations.append(
            f"Source {src.full_notation}: RINE prefix (100.x.x.x) "
            "MUST NOT appear on non-peering interfaces"
        )
    if dst.is_rine_prefix():
        violations.append(
            f"Destination {dst.full_notation}: RINE prefix (100.x.x.x) "
            "MUST NOT be globally routed"
        )

    # Interior link MUST NOT be routed externally (Section 18.4)
    if src.is_interior_link():
        violations.append(
            f"Source {src.full_notation}: interior link (222.x.x.x host) "
            "MUST NOT be routed externally"
        )
    if dst.is_interior_link():
        violations.append(
            f"Destination {dst.full_notation}: interior link (222.x.x.x host) "
            "MUST NOT be routed externally"
        )

    # Broadcast MUST NOT be routed (Section 12)
    if dst.is_broadcast():
        violations.append(
            f"Destination {dst.full_notation}: broadcast "
            "MUST NOT be routed beyond local segment"
        )

    return violations


def check_asn_reservation(asn: int) -> str | None:
    """Check if an ASN is in a reserved range that MUST NOT be allocated.

    Returns a violation description or None if OK.
    """
    if _INTERNAL_ZONE_ASN_MIN <= asn <= _INTERNAL_ZONE_ASN_MAX:
        return (
            f"ASN {asn} is in the internal zone reserved range "
            f"({_INTERNAL_ZONE_ASN_MIN}-{_INTERNAL_ZONE_ASN_MAX}) "
            "and MUST NOT be allocated for public internet routing"
        )
    if _RINE_ASN_MIN <= asn <= _RINE_ASN_MAX:
        return (
            f"ASN {asn} is in the RINE reserved range "
            f"({_RINE_ASN_MIN}-{_RINE_ASN_MAX}) "
            "and MUST NOT be allocated for public internet routing"
        )
    if asn == PRIVATE_PEERING_ASN:
        return (
            f"ASN {asn} is reserved for private inter-company BGP8 peering "
            "per Section 4.8 (consistent with RFC 6996)"
        )
    if asn == DOCUMENTATION_ASN:
        return (
            f"ASN {asn} is reserved for documentation and testing "
            "per Section 4.8"
        )
    return None
