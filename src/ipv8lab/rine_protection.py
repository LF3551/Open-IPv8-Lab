# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""RINE Prefix Protection per draft-thain-ipv8-02 Section 19.3.

The 100.x.x.x RINE prefix MUST NOT appear in eBGP8 advertisements
or on non-peering interfaces.  NetLog8 SEC-ALERT MUST be generated
for each violation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from ipv8lab.address import IPv8Address


# ---------------------------------------------------------------------------
# Interface type
# ---------------------------------------------------------------------------

class InterfaceType(str, Enum):
    PEERING = "peering"        # IXP / private interconnect — RINE allowed
    EXTERNAL = "external"      # eBGP8 uplink — RINE forbidden
    INTERNAL = "internal"      # iBGP8 / OSPF8 — RINE forbidden


# ---------------------------------------------------------------------------
# Alert
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class SecurityAlert:
    """NetLog8 SEC-ALERT for a RINE prefix violation."""

    severity: str = "SEC-ALERT"
    source: str = ""
    interface: str = ""
    interface_type: str = ""
    violation: str = ""
    address: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "severity": self.severity,
            "source": self.source,
            "interface": self.interface,
            "interface_type": self.interface_type,
            "violation": self.violation,
            "address": self.address,
        }


# ---------------------------------------------------------------------------
# Filter result
# ---------------------------------------------------------------------------

class FilterAction(str, Enum):
    ACCEPT = "accept"
    DROP = "drop"


@dataclass(frozen=True, slots=True)
class FilterResult:
    action: FilterAction
    reason: str = ""
    alert: SecurityAlert | None = None


# ---------------------------------------------------------------------------
# RINE Prefix Filter
# ---------------------------------------------------------------------------

def is_rine_prefix(addr: IPv8Address) -> bool:
    """True if r.r.r.r is in 100.0.0.0/8."""
    return addr.routing_prefix[0] == 100


@dataclass
class RINEPrefixFilter:
    """Border router RINE prefix filter per Section 19.3.

    Parameters:
        router_id:  Identifier of the router running this filter.
    """

    router_id: str = "border-1"
    _alerts: list[SecurityAlert] = field(default_factory=list, init=False)

    # -- packet filtering ----------------------------------------------------

    def filter_packet(
        self,
        addr: IPv8Address,
        interface: str,
        iface_type: InterfaceType,
    ) -> FilterResult:
        """Filter a packet based on its source/destination r.r.r.r.

        RINE prefixes are allowed ONLY on peering interfaces.
        """
        if not is_rine_prefix(addr):
            return FilterResult(action=FilterAction.ACCEPT)

        if iface_type == InterfaceType.PEERING:
            return FilterResult(action=FilterAction.ACCEPT, reason="RINE on peering interface — allowed")

        alert = SecurityAlert(
            source=self.router_id,
            interface=interface,
            interface_type=iface_type.value,
            violation="RINE prefix on non-peering interface",
            address=addr.full_notation,
        )
        self._alerts.append(alert)
        return FilterResult(
            action=FilterAction.DROP,
            reason="100.x.x.x MUST NOT appear on non-peering interfaces (Section 19.3)",
            alert=alert,
        )

    # -- BGP8 advertisement filtering ----------------------------------------

    def filter_bgp8_advertisement(
        self,
        prefix: IPv8Address,
        interface: str,
    ) -> FilterResult:
        """Filter a BGP8 route advertisement.

        RINE prefixes MUST NOT appear in eBGP8 advertisements.
        """
        if not is_rine_prefix(prefix):
            return FilterResult(action=FilterAction.ACCEPT)

        alert = SecurityAlert(
            source=self.router_id,
            interface=interface,
            interface_type="ebgp8",
            violation="RINE prefix in eBGP8 advertisement",
            address=prefix.full_notation,
        )
        self._alerts.append(alert)
        return FilterResult(
            action=FilterAction.DROP,
            reason="100.x.x.x MUST NOT appear in eBGP8 advertisements (Section 19.3)",
            alert=alert,
        )

    # -- batch ---------------------------------------------------------------

    def filter_batch(
        self,
        addresses: list[tuple[IPv8Address, str, InterfaceType]],
    ) -> list[FilterResult]:
        """Filter multiple packets at once."""
        return [self.filter_packet(a, iface, it) for a, iface, it in addresses]

    # -- inspection ----------------------------------------------------------

    @property
    def alerts(self) -> list[SecurityAlert]:
        return list(self._alerts)

    def clear_alerts(self) -> int:
        n = len(self._alerts)
        self._alerts.clear()
        return n

    def summary(self) -> dict[str, object]:
        return {
            "router_id": self.router_id,
            "alert_count": len(self._alerts),
        }
