# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Cloud Provider VPC simulation per draft-thain-ipv8-02 Section 17.

IPv8 resolves VPC address overlap, VPC peering complexity, and
multi-cloud routing through ASN-based disambiguation.  The 127.x.x.x
internal zone prefix enables cloud providers to assign unique zone
prefixes to customer VPCs without address renumbering.

Each customer VPC receives a unique 127.x.x.x zone prefix — no two
customer networks can overlap regardless of RFC 1918 address reuse
within each VPC.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ipv8lab.address import IPv8Address


# ---------------------------------------------------------------------------
# VPC entry
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class VPC:
    """One customer VPC with a unique zone prefix."""

    vpc_id: str
    customer: str
    zone_prefix: tuple[int, int, int, int]   # 127.x.x.x
    cidr: str                                 # e.g. "10.0.0.0/16"

    @property
    def zone_prefix_str(self) -> str:
        return ".".join(str(o) for o in self.zone_prefix)

    def contains(self, addr: IPv8Address) -> bool:
        """True if *addr* belongs to this VPC's zone prefix."""
        return addr.routing_prefix == self.zone_prefix

    def to_dict(self) -> dict[str, str]:
        return {
            "vpc_id": self.vpc_id,
            "customer": self.customer,
            "zone_prefix": self.zone_prefix_str,
            "cidr": self.cidr,
        }


# ---------------------------------------------------------------------------
# Peering link
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class VPCPeering:
    """A peering link between two VPCs."""

    vpc_a: str
    vpc_b: str

    def to_dict(self) -> dict[str, str]:
        return {"vpc_a": self.vpc_a, "vpc_b": self.vpc_b}


# ---------------------------------------------------------------------------
# Cloud Provider VPC Fabric
# ---------------------------------------------------------------------------

@dataclass
class CloudVPCFabric:
    """Cloud provider VPC fabric assigning 127.x.x.x zone prefixes.

    Parameters:
        provider_asn: The cloud provider's ASN.
    """

    provider_asn: int = 64496
    _vpcs: dict[str, VPC] = field(default_factory=dict, init=False)
    _peerings: list[VPCPeering] = field(default_factory=list, init=False)
    _next_zone: int = field(default=1, init=False)   # next zone id (127.X.0.0)

    # -- VPC management ------------------------------------------------------

    def create_vpc(
        self,
        vpc_id: str,
        customer: str,
        cidr: str = "10.0.0.0/16",
    ) -> VPC:
        """Create a new VPC with a unique 127.x.x.x zone prefix."""
        if vpc_id in self._vpcs:
            msg = f"VPC {vpc_id!r} already exists"
            raise ValueError(msg)
        zone = self._next_zone
        self._next_zone += 1
        if zone > 126:
            # Skip 127 — reserved for interop (127.127.0.0)
            zone = self._next_zone
            self._next_zone += 1
        prefix = (127, zone, 0, 0)
        vpc = VPC(vpc_id=vpc_id, customer=customer, zone_prefix=prefix, cidr=cidr)
        self._vpcs[vpc_id] = vpc
        return vpc

    def get_vpc(self, vpc_id: str) -> VPC | None:
        return self._vpcs.get(vpc_id)

    def list_vpcs(self) -> list[VPC]:
        return list(self._vpcs.values())

    def delete_vpc(self, vpc_id: str) -> bool:
        if vpc_id in self._vpcs:
            del self._vpcs[vpc_id]
            self._peerings = [
                p for p in self._peerings
                if p.vpc_a != vpc_id and p.vpc_b != vpc_id
            ]
            return True
        return False

    # -- peering -------------------------------------------------------------

    def create_peering(self, vpc_a: str, vpc_b: str) -> VPCPeering:
        """Create a peering link between two VPCs."""
        if vpc_a not in self._vpcs:
            msg = f"VPC {vpc_a!r} not found"
            raise ValueError(msg)
        if vpc_b not in self._vpcs:
            msg = f"VPC {vpc_b!r} not found"
            raise ValueError(msg)
        if vpc_a == vpc_b:
            msg = "Cannot peer a VPC with itself"
            raise ValueError(msg)
        # Check for duplicate
        for p in self._peerings:
            if {p.vpc_a, p.vpc_b} == {vpc_a, vpc_b}:
                return p
        peering = VPCPeering(vpc_a=vpc_a, vpc_b=vpc_b)
        self._peerings.append(peering)
        return peering

    def list_peerings(self) -> list[VPCPeering]:
        return list(self._peerings)

    # -- routing / lookup ----------------------------------------------------

    def resolve_vpc(self, addr: IPv8Address) -> VPC | None:
        """Find which VPC an address belongs to (by zone prefix)."""
        for vpc in self._vpcs.values():
            if vpc.contains(addr):
                return vpc
        return None

    def can_communicate(self, src: IPv8Address, dst: IPv8Address) -> bool:
        """Check if *src* can reach *dst* through VPC peering or same VPC."""
        src_vpc = self.resolve_vpc(src)
        dst_vpc = self.resolve_vpc(dst)
        if src_vpc is None or dst_vpc is None:
            return False
        if src_vpc.vpc_id == dst_vpc.vpc_id:
            return True
        for p in self._peerings:
            if {p.vpc_a, p.vpc_b} == {src_vpc.vpc_id, dst_vpc.vpc_id}:
                return True
        return False

    # -- validation ----------------------------------------------------------

    def validate_no_overlap(self) -> list[str]:
        """Verify that no two VPCs share a zone prefix (should be impossible)."""
        prefixes: dict[tuple[int, int, int, int], str] = {}
        issues: list[str] = []
        for vpc in self._vpcs.values():
            if vpc.zone_prefix in prefixes:
                issues.append(
                    f"Overlap: {vpc.vpc_id} and {prefixes[vpc.zone_prefix]} share {vpc.zone_prefix_str}"
                )
            prefixes[vpc.zone_prefix] = vpc.vpc_id
        return issues

    # -- summary -------------------------------------------------------------

    def summary(self) -> dict[str, object]:
        return {
            "provider_asn": self.provider_asn,
            "vpc_count": len(self._vpcs),
            "peering_count": len(self._peerings),
            "overlap_issues": len(self.validate_no_overlap()),
        }
