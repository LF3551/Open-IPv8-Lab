# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Cost Factor (CF) metric per draft-thain-ipv8-02 Section 1.6.

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
