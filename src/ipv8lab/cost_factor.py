# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Cost Factor (CF) metric per draft-thain-ipv8- Section 1.6.

CF is a 32-bit accumulated metric derived from seven components
measured from TCP session telemetry:

  1. Round trip time (RTT)
  2. Packet loss
  3. Congestion window state
  4. Session stability
  5. Link capacity
  6. Economic policy
  7. Geographic distance (physics floor)

CF accumulates across every BGP8 hop from source to destination.
Every router independently selects the path with the lowest
accumulated CF without coordination.

The geographic component sets a physics floor — no path can appear
better than the speed of light over the great circle distance allows.
A path that measures faster than physics permits is flagged as a
CF anomaly.

CFv1 is the mandatory baseline.

Per Section 8.4:  CF_total = CF_external + CF_intrazone
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import IntEnum

# Speed of light in fibre (approx 2/3 of vacuum c), in km/ms
_C_FIBRE_KM_PER_MS = 200.0  # ~200 km/ms in fibre
_EARTH_RADIUS_KM = 6371.0


class CFVersion(IntEnum):
    """Cost Factor algorithm version."""

    V1 = 1


@dataclass(frozen=True, slots=True)
class CFComponents:
    """The seven CF metric components (all normalized to 0.0–1.0)."""

    rtt: float = 0.0              # Round trip time (normalized)
    packet_loss: float = 0.0      # Packet loss ratio (0.0–1.0)
    congestion: float = 0.0       # Congestion window state (0=open, 1=collapsed)
    stability: float = 0.0        # Session stability (0=stable, 1=unstable)
    capacity: float = 0.0         # Link capacity (0=high, 1=exhausted)
    economic: float = 0.0         # Economic policy (0=preferred, 1=expensive)
    geographic: float = 0.0       # Geographic distance (physics floor, normalized)

    def __post_init__(self) -> None:
        for name in (
            "rtt", "packet_loss", "congestion", "stability",
            "capacity", "economic", "geographic",
        ):
            val = getattr(self, name)
            if not 0.0 <= val <= 1.0:
                msg = f"CF component '{name}' must be 0.0–1.0, got {val}"
                raise ValueError(msg)


# CFv1 default weights for the 7 components
_CFV1_WEIGHTS: tuple[float, ...] = (
    0.25,   # rtt
    0.20,   # packet_loss
    0.10,   # congestion
    0.10,   # stability
    0.15,   # capacity
    0.05,   # economic
    0.15,   # geographic
)


def compute_cf(
    components: CFComponents,
    *,
    version: CFVersion = CFVersion.V1,
    weights: tuple[float, ...] | None = None,
) -> int:
    """Compute a 32-bit CF value from components.

    Returns an unsigned 32-bit integer (0 = best, 2^32-1 = worst).
    """
    if version != CFVersion.V1:
        msg = f"Unsupported CF version: {version}"
        raise ValueError(msg)

    w = weights if weights is not None else _CFV1_WEIGHTS
    if len(w) != 7:
        msg = f"Exactly 7 weights required, got {len(w)}"
        raise ValueError(msg)

    vals = (
        components.rtt,
        components.packet_loss,
        components.congestion,
        components.stability,
        components.capacity,
        components.economic,
        components.geographic,
    )

    weighted = sum(v * wt for v, wt in zip(vals, w))
    # Clamp and scale to 32-bit unsigned
    clamped = max(0.0, min(1.0, weighted))
    return int(clamped * 0xFFFFFFFF)


def accumulate_cf(hop_cfs: list[int]) -> int:
    """Accumulate CF values across BGP8 hops (saturating addition)."""
    total = 0
    for cf in hop_cfs:
        total = min(total + cf, 0xFFFFFFFF)
    return total


def cf_total(cf_external: int, cf_intrazone: int) -> int:
    """CF_total = CF_external + CF_intrazone (Section 8.4), saturating."""
    return min(cf_external + cf_intrazone, 0xFFFFFFFF)


def select_best_path(paths: dict[str, int]) -> str | None:
    """Select the path with the lowest accumulated CF.

    Args:
        paths: mapping of path_id → accumulated CF value

    Returns:
        path_id with lowest CF, or None if empty
    """
    if not paths:
        return None
    return min(paths, key=paths.__getitem__)


# --- Geographic physics floor ---


def great_circle_distance_km(
    lat1: float, lon1: float,
    lat2: float, lon2: float,
) -> float:
    """Haversine great-circle distance in kilometres."""
    lat1_r, lat2_r = math.radians(lat1), math.radians(lat2)
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)

    a = (
        math.sin(dlat / 2) ** 2
        + math.cos(lat1_r) * math.cos(lat2_r) * math.sin(dlon / 2) ** 2
    )
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return _EARTH_RADIUS_KM * c


def physics_floor_ms(distance_km: float) -> float:
    """Minimum one-way latency in ms based on speed of light in fibre."""
    return distance_km / _C_FIBRE_KM_PER_MS


def is_cf_anomaly(measured_rtt_ms: float, distance_km: float) -> bool:
    """Detect CF anomaly: measured RTT faster than physics allows.

    A path that appears faster than the speed of light over the
    great-circle distance is flagged as an anomaly.
    """
    min_rtt_ms = 2 * physics_floor_ms(distance_km)  # round-trip
    return measured_rtt_ms < min_rtt_ms


@dataclass(frozen=True, slots=True)
class CFPath:
    """A path with CF metadata."""

    path_id: str
    hops: list[int]  # per-hop CF values
    distance_km: float = 0.0
    measured_rtt_ms: float = 0.0

    @property
    def accumulated_cf(self) -> int:
        return accumulate_cf(self.hops)

    @property
    def anomaly(self) -> bool:
        if self.distance_km <= 0:
            return False
        return is_cf_anomaly(self.measured_rtt_ms, self.distance_km)


# ===========================================================================
# Step 11 — CF scope, IGP export interface, slow-slew
# ===========================================================================

class CFScope(IntEnum):
    """Scope of a Cost Factor value.

    CF is **only** valid as a BGP8 inter-AS path attribute
    (``INTER_AS``).  IGP metrics stay intra-AS and are never exported
    directly as CF — only the *derived* CF input reaches IBGP8.
    """

    INTER_AS = 1   # BGP8 path attribute — the only scope where CF travels
    INTRA_AS = 2   # IGP-internal; must not be exported as-is


class CFScopeViolation(Exception):
    """Raised when CF is used outside its permitted scope."""


def assert_inter_as(scope: CFScope, context: str = "") -> None:
    """Raise :class:`CFScopeViolation` if *scope* is not INTER_AS."""
    if scope != CFScope.INTER_AS:
        msg = f"CF must not be carried as intra-AS attribute{': ' + context if context else ''}"
        raise CFScopeViolation(msg)


# ---------------------------------------------------------------------------
# IGP metric → CF input conversion (IGP CF Export Interface)
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class IGPMetric:
    """Intra-AS routing metric from OSPF8/IS-IS8/IBGP8.

    *cost* is the raw IGP metric (e.g. OSPF cost, IS-IS metric).
    *bandwidth_mbps* and *utilization* are optional link attributes.
    These values stay inside the AS for IGP path selection; only the
    derived CF component (``to_cf_input()``) is surfaced to IBGP8.
    """

    cost: int = 1
    bandwidth_mbps: float = 1000.0
    utilization: float = 0.0      # 0.0–1.0

    def __post_init__(self) -> None:
        if not 0.0 <= self.utilization <= 1.0:
            msg = f"utilization must be 0.0–1.0, got {self.utilization}"
            raise ValueError(msg)
        if self.bandwidth_mbps <= 0:
            msg = f"bandwidth_mbps must be > 0, got {self.bandwidth_mbps}"
            raise ValueError(msg)

    def to_cf_input(self, max_cost: int = 1000) -> CFComponents:
        """Derive CF input components from this IGP metric.

        The IGP metric influences:
        - ``capacity``: from utilization
        - ``economic``: from relative cost (normalised to *max_cost*)

        All other components are zero — they will be filled by actual
        TCP telemetry when available.  This function *never* alters IGP
        path selection; it only maps metrics to CF vocabulary.
        """
        capacity = min(self.utilization, 1.0)
        economic = min(self.cost / max(max_cost, 1), 1.0)
        return CFComponents(
            rtt=0.0,
            packet_loss=0.0,
            congestion=0.0,
            stability=0.0,
            capacity=capacity,
            economic=economic,
            geographic=0.0,
        )


class IGPCFExporter:
    """Collects IGP metrics from multiple interfaces and exports CF inputs
    to IBGP8 **without** altering IGP path selection.

    Each interface (identified by name) contributes an :class:`IGPMetric`.
    Call :meth:`export_cf` to get the aggregate CF component for IBGP8.
    """

    def __init__(self) -> None:
        self._metrics: dict[str, IGPMetric] = {}

    def update(self, interface: str, metric: IGPMetric) -> None:
        """Register or update the IGP metric for *interface*."""
        self._metrics[interface] = metric

    def remove(self, interface: str) -> bool:
        if interface in self._metrics:
            del self._metrics[interface]
            return True
        return False

    def export_cf(self, max_cost: int = 1000) -> CFComponents | None:
        """Aggregate IGP metrics into a single CF input for IBGP8.

        Returns None if no metrics are registered.
        The aggregation takes the worst-case (max) across all interfaces
        for each component — conservative but safe for route selection.
        """
        if not self._metrics:
            return None
        inputs = [m.to_cf_input(max_cost) for m in self._metrics.values()]
        return CFComponents(
            rtt=0.0,
            packet_loss=0.0,
            congestion=0.0,
            stability=0.0,
            capacity=max(c.capacity for c in inputs),
            economic=max(c.economic for c in inputs),
            geographic=0.0,
        )

    @property
    def interface_count(self) -> int:
        return len(self._metrics)


# ---------------------------------------------------------------------------
# Slow-slew CF adjustment (prevents route flap)
# ---------------------------------------------------------------------------

@dataclass
class CFSlew:
    """Slow-slew rate limiter for CF changes.

    When the measured CF changes sharply, advertising the raw value
    immediately can cause route flap.  :class:`CFSlew` limits how much
    the *advertised* CF can change per update step.

    *max_step* is the maximum per-update change in CF units (0–0xFFFFFFFF).
    *decay* fraction is applied when the new CF is lower than current
    (improvement is also slewed to avoid oscillation).
    """

    max_step: int = 0x0FFFFFFF    # max per-step increase (~6.25% of range)
    decay: float = 0.1            # fraction of difference applied on improvement

    def __post_init__(self) -> None:
        if not 0.0 < self.decay <= 1.0:
            msg = f"decay must be in (0, 1], got {self.decay}"
            raise ValueError(msg)

    def step(self, current: int, target: int) -> int:
        """Compute the next advertised CF value.

        - If *target* > *current* (degradation): advance by at most
          ``max_step``.
        - If *target* < *current* (improvement): advance by ``decay``
          fraction of the difference (exponential smoothing).
        - If equal: return unchanged.
        """
        if target > current:
            return min(current + self.max_step, target)
        if target < current:
            delta = int((current - target) * self.decay)
            return max(current - max(delta, 1), target)
        return current

    def converged(self, current: int, target: int, tolerance: int = 0) -> bool:
        """True when *current* is within *tolerance* of *target*."""
        return abs(current - target) <= tolerance
