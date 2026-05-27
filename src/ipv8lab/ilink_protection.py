# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Interior Link Convention Protection per draft-thain-ipv8- Section 19.4.

Border routers MUST filter received BGP8 advertisements containing
n.n.n.n addresses in the 222.0.0.0/8 range.  NetLog8 E3 trap MUST be
generated for each violation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from ipv8lab.address import IPv8Address


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------

INTERIOR_LINK_FIRST_OCTET = 222


def is_interior_link_host(addr: IPv8Address) -> bool:
    """True if n.n.n.n is in 222.0.0.0/8."""
    return addr.host_part[0] == INTERIOR_LINK_FIRST_OCTET


# ---------------------------------------------------------------------------
# E3 trap
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class E3Trap:
    """NetLog8 E3 trap for an interior link convention violation."""

    severity: str = "E3"
    source: str = ""
    interface: str = ""
    violation: str = ""
    address: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "severity": self.severity,
            "source": self.source,
            "interface": self.interface,
            "violation": self.violation,
            "address": self.address,
        }


# ---------------------------------------------------------------------------
# Filter action
# ---------------------------------------------------------------------------

class FilterAction(str, Enum):
    ACCEPT = "accept"
    DROP = "drop"


@dataclass(frozen=True, slots=True)
class FilterResult:
    action: FilterAction
    reason: str = ""
    trap: E3Trap | None = None


# ---------------------------------------------------------------------------
# Interior Link Filter
# ---------------------------------------------------------------------------

@dataclass
class InteriorLinkFilter:
    """Border router 222.0.0.0/8 BGP8 filter per Section 19.4."""

    router_id: str = "border-1"
    _traps: list[E3Trap] = field(default_factory=list, init=False)

    # -- BGP8 advertisement filtering ----------------------------------------

    def filter_bgp8_advertisement(
        self,
        prefix: IPv8Address,
        interface: str = "eth0",
    ) -> FilterResult:
        """Filter a BGP8 route advertisement.

        Advertisements with n.n.n.n in 222.0.0.0/8 MUST be rejected.
        """
        if not is_interior_link_host(prefix):
            return FilterResult(action=FilterAction.ACCEPT)

        trap = E3Trap(
            source=self.router_id,
            interface=interface,
            violation="Interior link address in BGP8 advertisement",
            address=prefix.full_notation,
        )
        self._traps.append(trap)
        return FilterResult(
            action=FilterAction.DROP,
            reason="222.0.0.0/8 in n.n.n.n MUST NOT appear in BGP8 advertisements (Section 19.4)",
            trap=trap,
        )

    # -- packet filtering (egress) -------------------------------------------

    def filter_packet(
        self,
        addr: IPv8Address,
        interface: str = "eth0",
    ) -> FilterResult:
        """Filter a packet at egress — interior link addresses must not leave the AS."""
        if not is_interior_link_host(addr):
            return FilterResult(action=FilterAction.ACCEPT)

        trap = E3Trap(
            source=self.router_id,
            interface=interface,
            violation="Interior link address in egress packet",
            address=addr.full_notation,
        )
        self._traps.append(trap)
        return FilterResult(
            action=FilterAction.DROP,
            reason="222.0.0.0/8 MUST NOT be routed externally (Section 19.4)",
            trap=trap,
        )

    # -- batch ---------------------------------------------------------------

    def filter_batch(
        self,
        advertisements: list[tuple[IPv8Address, str]],
    ) -> list[FilterResult]:
        """Filter multiple BGP8 advertisements."""
        return [self.filter_bgp8_advertisement(a, iface) for a, iface in advertisements]

    # -- inspection ----------------------------------------------------------

    @property
    def traps(self) -> list[E3Trap]:
        return list(self._traps)

    def clear_traps(self) -> int:
        n = len(self._traps)
        self._traps.clear()
        return n

    def summary(self) -> dict[str, object]:
        return {
            "router_id": self.router_id,
            "trap_count": len(self._traps),
        }
