# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""ARP8-driven version selection per draft-thain-ipv8- Section 2.

Implements neighbor capability discovery (dual ARP8/ARP4 probe),
per-hop version selection, and router forwarding with IPv8→IPv4 downgrade.
"""

from __future__ import annotations

import enum
import time
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# 2.1  Neighbor capability
# ---------------------------------------------------------------------------

class NeighborCapability(enum.Enum):
    """Capability recorded in the ARP8 cache after dual-probe discovery."""

    IPV8 = "ipv8"
    IPV4_ONLY = "ipv4_only"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# 2.2  ARP8 cache entry with capability
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class ARP8VersionEntry:
    """ARP8 cache entry extended with version capability (Section 2.2)."""

    ipv8_address: str
    mac_address: str
    capability: NeighborCapability = NeighborCapability.UNKNOWN
    discovered_at: float = 0.0
    ttl: float = 14400.0  # 4 hours default

    def is_expired(self, now: float) -> bool:
        return now - self.discovered_at >= self.ttl


# ---------------------------------------------------------------------------
# 2.2  Dual probe result
# ---------------------------------------------------------------------------

class ProbeResult(enum.Enum):
    """Outcome of the dual ARP8/ARP4 probe."""

    ARP8_RESPONDED = "arp8_responded"
    ARP4_RESPONDED = "arp4_responded"
    NO_RESPONSE = "no_response"


@dataclass(slots=True)
class DualProbeOutcome:
    """Result of a dual probe toward a neighbor."""

    target_ip: str
    probe_result: ProbeResult
    capability: NeighborCapability
    arp8_sent_at: float = 0.0
    arp4_sent_at: float = 0.0
    response_at: float = 0.0
    mac_address: str = ""


# ---------------------------------------------------------------------------
# Version-aware ARP8 cache
# ---------------------------------------------------------------------------

class ARP8VersionCache:
    """ARP8 cache with per-neighbor capability tracking (Section 2.1–2.2)."""

    def __init__(self) -> None:
        self._entries: dict[str, ARP8VersionEntry] = {}

    # -- dual probe simulation -----------------------------------------------

    def discover_neighbor(
        self,
        target_ip: str,
        *,
        responds_arp8: bool = True,
        mac_address: str = "00:00:00:00:00:00",
    ) -> DualProbeOutcome:
        """Simulate dual probe per Section 2.2.

        ``responds_arp8`` controls whether the simulated neighbor answers
        the ARP8 probe (True) or only the ARP4 fallback (False).
        """
        now = time.time()
        arp8_sent = now
        arp4_sent = now + 0.050  # +50 ms per spec

        if responds_arp8:
            result = ProbeResult.ARP8_RESPONDED
            cap = NeighborCapability.IPV8
            resp_time = arp8_sent + 0.001  # simulated 1 ms RTT
        else:
            result = ProbeResult.ARP4_RESPONDED
            cap = NeighborCapability.IPV4_ONLY
            resp_time = arp4_sent + 0.001

        entry = ARP8VersionEntry(
            ipv8_address=target_ip,
            mac_address=mac_address,
            capability=cap,
            discovered_at=resp_time,
        )
        self._entries[target_ip] = entry

        return DualProbeOutcome(
            target_ip=target_ip,
            probe_result=result,
            capability=cap,
            arp8_sent_at=arp8_sent,
            arp4_sent_at=arp4_sent,
            response_at=resp_time,
            mac_address=mac_address,
        )

    # -- cache operations ----------------------------------------------------

    def get(self, ip: str) -> ARP8VersionEntry | None:
        return self._entries.get(ip)

    def capability_of(self, ip: str) -> NeighborCapability:
        entry = self._entries.get(ip)
        if entry is None:
            return NeighborCapability.UNKNOWN
        return entry.capability

    def learn(self, entry: ARP8VersionEntry) -> None:
        self._entries[entry.ipv8_address] = entry

    def flush(self) -> int:
        n = len(self._entries)
        self._entries.clear()
        return n

    def flush_expired(self) -> int:
        now = time.time()
        expired = [k for k, v in self._entries.items() if v.is_expired(now)]
        for k in expired:
            del self._entries[k]
        return len(expired)

    def all_entries(self) -> list[ARP8VersionEntry]:
        return list(self._entries.values())

    @property
    def size(self) -> int:
        return len(self._entries)


# ---------------------------------------------------------------------------
# 2.3  Transmitted frame descriptor
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class TransmittedFrame:
    """Descriptor of a packet as placed on the wire after version selection."""

    ip_version: int  # 4 or 8
    src: str
    dst: str
    payload_hint: str = ""
    downgraded: bool = False


# ---------------------------------------------------------------------------
# 2.3  Version selector
# ---------------------------------------------------------------------------

class VersionSelector:
    """Select IP version per neighbor capability (Section 2.3).

    Given a full IPv8 src/dst (r.r.r.r.n.n.n.n) and the neighbor's
    recorded capability, produce the on-wire frame descriptor.
    """

    @staticmethod
    def select(
        src_full: str,
        dst_full: str,
        neighbor_cap: NeighborCapability,
    ) -> TransmittedFrame:
        if neighbor_cap == NeighborCapability.IPV8:
            return TransmittedFrame(
                ip_version=8,
                src=src_full,
                dst=dst_full,
            )
        # IPv4-only or unknown → downgrade
        src_host = _host_part(src_full)
        dst_host = _host_part(dst_full)
        return TransmittedFrame(
            ip_version=4,
            src=src_host,
            dst=dst_host,
            downgraded=True,
        )


# ---------------------------------------------------------------------------
# 2.4  Router interface
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class RouterInterface:
    """A router's outgoing interface with its own ARP8 cache."""

    name: str
    cache: ARP8VersionCache = field(default_factory=ARP8VersionCache)


# ---------------------------------------------------------------------------
# 2.4  Router forwarder
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class ForwardDecision:
    """Result of a router forwarding decision (Section 2.4)."""

    outgoing_interface: str
    frame: TransmittedFrame
    xlate8_needed: bool = False


class RouterForwarder:
    """IPv8 router that applies per-interface version selection (Section 2.4).

    A single router MAY serve IPv8-capable and IPv4-only devices on
    different interfaces simultaneously.
    """

    def __init__(self) -> None:
        self._interfaces: dict[str, RouterInterface] = {}

    def add_interface(self, name: str) -> RouterInterface:
        iface = RouterInterface(name=name)
        self._interfaces[name] = iface
        return iface

    def get_interface(self, name: str) -> RouterInterface | None:
        return self._interfaces.get(name)

    @property
    def interfaces(self) -> list[RouterInterface]:
        return list(self._interfaces.values())

    def forward(
        self,
        src_full: str,
        dst_full: str,
        outgoing_iface: str,
        next_hop_ip: str,
    ) -> ForwardDecision:
        """Forward a packet through *outgoing_iface* to *next_hop_ip*.

        If the next-hop is IPv4-only the router MUST downgrade the
        packet at the outgoing interface (Section 2.4).
        """
        iface = self._interfaces.get(outgoing_iface)
        if iface is None:
            raise ValueError(f"Unknown interface: {outgoing_iface}")

        cap = iface.cache.capability_of(next_hop_ip)
        frame = VersionSelector.select(src_full, dst_full, cap)

        xlate8_needed = frame.downgraded
        return ForwardDecision(
            outgoing_interface=outgoing_iface,
            frame=frame,
            xlate8_needed=xlate8_needed,
        )


# ---------------------------------------------------------------------------
# 2.5  Attribution helper
# ---------------------------------------------------------------------------

def has_asn_attribution(frame: TransmittedFrame) -> bool:
    """Section 2.5: ASN attribution applies only when both endpoints
    are IPv8-capable (ip_version == 8)."""
    return frame.ip_version == 8


# ---------------------------------------------------------------------------
# 2.6  Transition summary
# ---------------------------------------------------------------------------

TRANSITION_PROPERTIES: list[str] = [
    "IPv4-only endpoints never require modification.",
    "IPv4 devices on a shared segment with IPv8 devices continue to operate without configuration change.",
    "IPv4 devices behind IPv8 routers continue to operate because the router downgrades at the boundary.",
    "IPv4 applications on IPv8 hosts continue to operate because XLATE8 handles version translation.",
    "No IPv4 device ever receives a packet with version 8 in the IP header.",
    "Transition is per-device and per-router, on each operator's own schedule.",
]


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _host_part(ipv8_addr: str) -> str:
    """Extract n.n.n.n from r.r.r.r.n.n.n.n (dotted 8-octet form)."""
    parts = ipv8_addr.split(".")
    if len(parts) == 8:
        return ".".join(parts[4:])
    # already 4-part or ASN.n.n.n.n
    if len(parts) == 5:
        return ".".join(parts[1:])
    return ipv8_addr


def _asn_part(ipv8_addr: str) -> str:
    """Extract r.r.r.r from r.r.r.r.n.n.n.n."""
    parts = ipv8_addr.split(".")
    if len(parts) == 8:
        return ".".join(parts[:4])
    return "0.0.0.0"


# ---------------------------------------------------------------------------
# ARP8 Primary RN Discovery (spec §3.2)
# ---------------------------------------------------------------------------

class PrimaryRNConflictSeverity(enum.Enum):
    """Severity of a Primary RN conflict detected on a segment."""

    CONFLICT = "conflict"   # Neighbour advertising a different Primary RN


@dataclass(slots=True)
class PrimaryRNConflict:
    """A Primary RN conflict detected by ARP8 Primary RN Discovery."""

    interface: str
    expected_rn: int          # Our segment's Primary RN
    observed_rn: int          # RN seen in the neighbour's announcement
    neighbour_addr: str       # Canonical neighbour address
    detected_at: float = 0.0
    severity: PrimaryRNConflictSeverity = PrimaryRNConflictSeverity.CONFLICT

    @property
    def netlog8_event(self) -> str:
        """Produce a NetLog8 SEC-ALERT event string for this conflict."""
        return (
            f"SEC-ALERT primary-rn-conflict iface={self.interface} "
            f"expected_rn={self.expected_rn} observed_rn={self.observed_rn} "
            f"neighbour={self.neighbour_addr}"
        )


class PrimaryRNDiscovery:
    """ARP8 Primary RN Discovery engine for a single network interface.

    Monitors neighbour Primary RN announcements and detects any that
    differ from the segment's expected Primary RN.  On conflict:

    * Records the conflict in :attr:`conflicts`.
    * Sets :attr:`forwarding_suspended` to ``True`` (operator must
      clear it explicitly via :meth:`clear_conflict`).
    * The conflict can be retrieved as a NetLog8 SEC-ALERT string via
      :attr:`~PrimaryRNConflict.netlog8_event`.
    """

    def __init__(self, interface: str, expected_rn: int) -> None:
        self.interface = interface
        self.expected_rn = expected_rn
        self.forwarding_suspended: bool = False
        self.conflicts: list[PrimaryRNConflict] = []

    def observe(self, neighbour_addr: str, announced_rn: int) -> PrimaryRNConflict | None:
        """Process a neighbour Primary RN announcement.

        Returns a :class:`PrimaryRNConflict` if the announced RN
        differs from :attr:`expected_rn`, otherwise ``None``.
        """
        if announced_rn == self.expected_rn:
            return None
        conflict = PrimaryRNConflict(
            interface=self.interface,
            expected_rn=self.expected_rn,
            observed_rn=announced_rn,
            neighbour_addr=neighbour_addr,
            detected_at=time.monotonic(),
        )
        self.conflicts.append(conflict)
        self.forwarding_suspended = True
        return conflict

    def clear_conflict(self) -> None:
        """Clear all recorded conflicts and resume forwarding."""
        self.conflicts.clear()
        self.forwarding_suspended = False
