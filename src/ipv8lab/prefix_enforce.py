# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""/16 Minimum Prefix Enforcement at eBGP8 boundaries per Section 19.7.

Prefixes more specific than /16 MUST NOT be accepted from external BGP8
peers.  Such advertisements MUST be rejected and logged via NetLog8 as
SEC-ALERT.

Also enforces Section 9.3: the minimum injectable prefix at inter-AS
boundaries is /16.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from ipv8lab.address import IPv8Address


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MIN_PREFIX_LENGTH = 16  # /16 is the most specific allowed at eBGP8 boundaries


# ---------------------------------------------------------------------------
# Alert
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class SecurityAlert:
    """NetLog8 SEC-ALERT for a prefix length violation."""

    severity: str = "SEC-ALERT"
    source: str = ""
    interface: str = ""
    peer_asn: int = 0
    violation: str = ""
    prefix: str = ""
    prefix_length: int = 0

    def to_dict(self) -> dict[str, str | int]:
        return {
            "severity": self.severity,
            "source": self.source,
            "interface": self.interface,
            "peer_asn": self.peer_asn,
            "violation": self.violation,
            "prefix": self.prefix,
            "prefix_length": self.prefix_length,
        }


# ---------------------------------------------------------------------------
# Filter action
# ---------------------------------------------------------------------------

class FilterAction(str, Enum):
    ACCEPT = "accept"
    REJECT = "reject"


@dataclass(frozen=True, slots=True)
class FilterResult:
    action: FilterAction
    reason: str = ""
    alert: SecurityAlert | None = None


# ---------------------------------------------------------------------------
# BGP8 prefix advertisement
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class BGP8PrefixAd:
    """A BGP8 prefix advertisement received from an external peer."""

    prefix: IPv8Address
    prefix_length: int
    peer_asn: int = 0

    @property
    def cidr(self) -> str:
        return f"{self.prefix.canonical}/{self.prefix_length}"

    def is_too_specific(self) -> bool:
        """True if the prefix is more specific than /16."""
        return self.prefix_length > MIN_PREFIX_LENGTH


# ---------------------------------------------------------------------------
# Prefix Enforcer
# ---------------------------------------------------------------------------

@dataclass
class PrefixEnforcer:
    """eBGP8 /16 minimum prefix enforcement filter per Section 19.7.

    Parameters:
        router_id: Identifier of the border router running this filter.
    """

    router_id: str = "border-1"
    _alerts: list[SecurityAlert] = field(default_factory=list, init=False)
    _accepted: int = field(default=0, init=False)
    _rejected: int = field(default=0, init=False)

    # -- filtering -----------------------------------------------------------

    def filter_advertisement(
        self,
        ad: BGP8PrefixAd,
        interface: str = "eth0",
    ) -> FilterResult:
        """Filter a BGP8 prefix advertisement.

        Prefixes more specific than /16 MUST be rejected (Section 19.7).
        """
        if not ad.is_too_specific():
            self._accepted += 1
            return FilterResult(action=FilterAction.ACCEPT)

        alert = SecurityAlert(
            source=self.router_id,
            interface=interface,
            peer_asn=ad.peer_asn,
            violation=f"Prefix /{ad.prefix_length} more specific than /{MIN_PREFIX_LENGTH}",
            prefix=ad.cidr,
            prefix_length=ad.prefix_length,
        )
        self._alerts.append(alert)
        self._rejected += 1
        return FilterResult(
            action=FilterAction.REJECT,
            reason=(
                f"/{ad.prefix_length} exceeds /{MIN_PREFIX_LENGTH} minimum — "
                "MUST NOT be accepted from eBGP8 peers (Section 19.7)"
            ),
            alert=alert,
        )

    def filter_batch(
        self,
        items: list[tuple[BGP8PrefixAd, str]],
    ) -> list[FilterResult]:
        """Filter a batch of advertisements."""
        return [self.filter_advertisement(ad, iface) for ad, iface in items]

    # -- alerts --------------------------------------------------------------

    @property
    def alerts(self) -> list[SecurityAlert]:
        return list(self._alerts)

    def clear_alerts(self) -> int:
        """Clear all alerts and return the count cleared."""
        n = len(self._alerts)
        self._alerts.clear()
        return n

    # -- stats ---------------------------------------------------------------

    def summary(self) -> dict[str, str | int]:
        return {
            "router_id": self.router_id,
            "min_prefix_length": MIN_PREFIX_LENGTH,
            "accepted": self._accepted,
            "rejected": self._rejected,
            "alert_count": len(self._alerts),
        }
