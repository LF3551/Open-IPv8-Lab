# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Device compliance tiers per draft-thain-ipv8- Section 17.1-17.3.

Validates device capability sets against IPv8 compliance requirements.
Also provides the :class:`Segment` abstraction enforcing the per-segment
one-Primary-RN invariant (spec §3.2).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum

from ipv8lab.address import IPv8Address


class Tier(IntEnum):
    """IPv8 device compliance tier."""

    TIER1 = 1  # End Device
    TIER2 = 2  # L2 Network Device
    TIER3 = 3  # L3 Network Device


# Section 17.1 — Tier 1 (End Device) mandatory capabilities
TIER1_REQUIRED: frozenset[str] = frozenset({
    "route8",
    "static_routes",
    "vrf_management",
    "dual_default_gateway",
    "dhcp8_client",
    "arp8",
    "icmpv8",
    "zoneserver_tcp443",
    "netlog8_client",
    "acl8_client",
    "mgmt_vrf_4090",
    "oob_vrf_4091",
    "gratuitous_arp8",
})

TIER1_OPTIONAL: frozenset[str] = frozenset({
    "ospf8",
    "isis8",
    "ebgp8",
    "ibgp8",
})

# Section 17.2 — Tier 2 (L2 Network Device) mandatory capabilities
TIER2_REQUIRED: frozenset[str] = frozenset({
    "dot1q_trunking",
    "vlan_auto_creation",
    "mgmt_vrf_4090",
    "oob_vrf_4091",
    "oauth2_port_binding",
    "lldp",
    "netlog8_client",
    "arp8_mgmt",
    "icmpv8_mgmt",
    "pvrst",
    "zoneserver_pvrst_root",
    "sticky_mac",
    "zoneserver_mac_notify",
})

# Section 17.3 — Tier 3 (L3 Network Device) mandatory capabilities
# Includes all Tier 1 + additional L3 requirements
TIER3_REQUIRED: frozenset[str] = TIER1_REQUIRED | frozenset({
    "ebgp8",
    "ibgp8",
    "ospf8",
    "isis8_available",
    "vrf_full",
    "xlate8",
    "whois8_resolver",
    "acl8_gateway",
    "zoneserver_services",
    "pvrst_root",
    "oauth2_port_binding",
})

_TIER_REQUIREMENTS: dict[Tier, frozenset[str]] = {
    Tier.TIER1: TIER1_REQUIRED,
    Tier.TIER2: TIER2_REQUIRED,
    Tier.TIER3: TIER3_REQUIRED,
}


@dataclass(frozen=True, slots=True)
class ComplianceResult:
    """Result of a compliance check."""

    tier: Tier
    compliant: bool
    present: frozenset[str]
    missing: frozenset[str]
    extra: frozenset[str] = field(default=frozenset())


def check_compliance(
    tier: Tier,
    capabilities: set[str] | frozenset[str],
) -> ComplianceResult:
    """Check whether a set of capabilities meets a tier's requirements."""
    required = _TIER_REQUIREMENTS[tier]
    caps = frozenset(capabilities)
    missing = required - caps
    extra = caps - required
    # For Tier 1, optional caps are not "extra"
    if tier == Tier.TIER1:
        extra = extra - TIER1_OPTIONAL
    return ComplianceResult(
        tier=tier,
        compliant=len(missing) == 0,
        present=caps & required,
        missing=missing,
        extra=extra,
    )


def highest_compliant_tier(
    capabilities: set[str] | frozenset[str],
) -> Tier | None:
    """Return the highest tier the capability set is compliant with."""
    result: Tier | None = None
    for tier in Tier:
        cr = check_compliance(tier, capabilities)
        if cr.compliant:
            result = tier
    return result


# ---------------------------------------------------------------------------
# Per-segment RN invariant (spec §3.2)
# ---------------------------------------------------------------------------

class SegmentViolation(Exception):
    """Raised when the per-segment one-Primary-RN invariant is violated."""


@dataclass
class Segment:
    """A broadcast segment with a single mandatory Primary RN.

    Spec §3.2 requires that every IPv4 address on every interface
    attached to this segment shares the same Primary RN, and that
    every IPv8-aware interface's *Primary* IPv8 address belongs to
    that same RN.  Secondary IPv8 addresses may use any RN.
    """

    primary_rn: int
    name: str = ""
    # primary IPv8 addresses on this segment (one per interface)
    _primary_addrs: list[IPv8Address] = field(default_factory=list, repr=False)
    # secondary IPv8 addresses (may have any RN)
    _secondary_addrs: list[IPv8Address] = field(default_factory=list, repr=False)

    def add_primary_address(self, addr: IPv8Address) -> None:
        """Register a Primary IPv8 address for this segment.

        Raises :exc:`SegmentViolation` if the address's RN does not
        match the segment's :attr:`primary_rn`.
        """
        if addr.rn != self.primary_rn:
            raise SegmentViolation(
                f"Primary address {addr.canonical} has RN {addr.rn}, "
                f"but segment '{self.name}' primary RN is {self.primary_rn}."
            )
        self._primary_addrs.append(addr)

    def add_secondary_address(self, addr: IPv8Address) -> None:
        """Register a Secondary IPv8 address (any RN permitted)."""
        self._secondary_addrs.append(addr)

    def validate(self) -> list[str]:
        """Return a list of violation strings (empty = compliant)."""
        violations: list[str] = []
        for addr in self._primary_addrs:
            if addr.rn != self.primary_rn:
                violations.append(
                    f"Primary address {addr.canonical} RN mismatch "
                    f"(expected {self.primary_rn}, got {addr.rn})"
                )
        return violations

    @property
    def primary_addresses(self) -> list[IPv8Address]:
        return list(self._primary_addrs)

    @property
    def secondary_addresses(self) -> list[IPv8Address]:
        return list(self._secondary_addrs)
