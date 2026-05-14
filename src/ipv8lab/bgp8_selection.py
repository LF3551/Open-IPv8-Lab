# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""BGP8 path selection with CF metric per Section 8.4.

Every BGP8 router independently selects the path with the lowest
accumulated Cost Factor (CF) — no coordination needed.  CF accumulates
across every hop from source to destination.

Path selection algorithm:
  1. Discard invalid prefixes (Section 8.3: /16 min for eBGP8)
  2. Prefer shortest AS-path (tie-break only when CF equal)
  3. Select lowest accumulated CF
  4. Flag CF anomalies (measured RTT faster than physics floor)

This module integrates:
  - companions.BGP8Advertisement / BGP8Peer / BGP8Table
  - cost_factor.compute_cf / accumulate_cf / CFComponents / CFPath
"""

from __future__ import annotations

from dataclasses import dataclass

from ipv8lab.companions import BGP8Advertisement, BGP8Peer
from ipv8lab.cost_factor import (
    CFComponents,
    accumulate_cf,
    cf_total,
    compute_cf,
    is_cf_anomaly,
)


@dataclass(frozen=True, slots=True)
class PathCandidate:
    """A BGP8 path candidate with per-hop CF breakdown."""

    advertisement: BGP8Advertisement
    hop_cfs: tuple[int, ...] = ()
    distance_km: float = 0.0
    measured_rtt_ms: float = 0.0

    @property
    def accumulated_cf(self) -> int:
        return accumulate_cf(list(self.hop_cfs))

    @property
    def as_path_length(self) -> int:
        return len(self.advertisement.as_path)

    @property
    def anomaly(self) -> bool:
        if self.distance_km <= 0:
            return False
        return is_cf_anomaly(self.measured_rtt_ms, self.distance_km)


@dataclass(frozen=True, slots=True)
class SelectionResult:
    """Result of BGP8 path selection."""

    best: PathCandidate | None
    candidates: tuple[PathCandidate, ...]
    rejected: tuple[PathCandidate, ...] = ()
    reason: str = ""

    @property
    def has_anomalies(self) -> bool:
        return any(c.anomaly for c in self.candidates)


class BGP8PathSelector:
    """BGP8 path selection engine with CF metric.

    Maintains a per-prefix RIB of path candidates and selects
    the best path using accumulated CF as the primary metric.
    """

    def __init__(self, local_asn: int) -> None:
        self._local_asn = local_asn
        self._rib: dict[str, list[PathCandidate]] = {}
        self._peers: dict[int, BGP8Peer] = {}  # ASN → peer
        self._intrazone_cf: int = 0

    @property
    def local_asn(self) -> int:
        return self._local_asn

    @property
    def intrazone_cf(self) -> int:
        return self._intrazone_cf

    @intrazone_cf.setter
    def intrazone_cf(self, value: int) -> None:
        self._intrazone_cf = max(0, min(value, 0xFFFFFFFF))

    def add_peer(self, peer: BGP8Peer) -> None:
        """Register a BGP8 peer."""
        self._peers[peer.asn] = peer

    def get_peer(self, asn: int) -> BGP8Peer | None:
        return self._peers.get(asn)

    @property
    def peer_count(self) -> int:
        return len(self._peers)

    def receive_advertisement(
        self,
        adv: BGP8Advertisement,
        hop_cfs: tuple[int, ...] = (),
        distance_km: float = 0.0,
        measured_rtt_ms: float = 0.0,
    ) -> bool:
        """Receive a BGP8 advertisement and add to RIB.

        Returns False if the advertisement is invalid (/16 violation
        or AS-path loop).
        """
        # Validate /16 minimum for eBGP8
        if not adv.is_valid_ebgp_prefix():
            return False

        # AS-path loop detection: reject if local ASN in path
        if self._local_asn in adv.as_path:
            return False

        candidate = PathCandidate(
            advertisement=adv,
            hop_cfs=hop_cfs,
            distance_km=distance_km,
            measured_rtt_ms=measured_rtt_ms,
        )
        if adv.prefix not in self._rib:
            self._rib[adv.prefix] = []
        self._rib[adv.prefix].append(candidate)
        return True

    def withdraw(self, prefix: str, origin_asn: int) -> bool:
        """Withdraw routes from a specific origin ASN."""
        if prefix not in self._rib:
            return False
        before = len(self._rib[prefix])
        self._rib[prefix] = [
            c for c in self._rib[prefix]
            if c.advertisement.origin_asn != origin_asn
        ]
        if not self._rib[prefix]:
            del self._rib[prefix]
        return len(self._rib.get(prefix, [])) < before

    def select(self, prefix: str) -> SelectionResult:
        """Run BGP8 path selection for a prefix.

        Selection order:
          1. Filter out invalid prefixes and anomalies (soft — flagged)
          2. Lowest accumulated CF wins
          3. Shortest AS-path breaks ties
          4. Lowest origin ASN breaks further ties
        """
        candidates = self._rib.get(prefix, [])
        if not candidates:
            return SelectionResult(best=None, candidates=(), reason="no paths")

        valid: list[PathCandidate] = []
        rejected: list[PathCandidate] = []

        for c in candidates:
            if not c.advertisement.is_valid_ebgp_prefix():
                rejected.append(c)
            else:
                valid.append(c)

        if not valid:
            return SelectionResult(
                best=None,
                candidates=tuple(candidates),
                rejected=tuple(rejected),
                reason="all paths invalid",
            )

        # Apply CF_total = CF_external + CF_intrazone
        def sort_key(c: PathCandidate) -> tuple[int, int, int]:
            external_cf = c.accumulated_cf
            total = cf_total(external_cf, self._intrazone_cf)
            return (total, c.as_path_length, c.advertisement.origin_asn)

        valid.sort(key=sort_key)
        best = valid[0]

        return SelectionResult(
            best=best,
            candidates=tuple(valid),
            rejected=tuple(rejected),
            reason="lowest CF",
        )

    def select_all(self) -> dict[str, SelectionResult]:
        """Run path selection for all known prefixes."""
        return {prefix: self.select(prefix) for prefix in self._rib}

    def best_path(self, prefix: str) -> PathCandidate | None:
        """Shortcut: return best candidate or None."""
        return self.select(prefix).best

    def known_prefixes(self) -> list[str]:
        return list(self._rib.keys())

    def candidate_count(self, prefix: str) -> int:
        return len(self._rib.get(prefix, []))

    def rib_size(self) -> int:
        return sum(len(v) for v in self._rib.values())

    def clear(self) -> None:
        self._rib.clear()


def build_advertisement(
    prefix: str,
    origin_asn: int,
    as_path: tuple[int, ...],
    next_hop: str = "",
    cf_components: CFComponents | None = None,
    prefix_length: int = 8,
) -> tuple[BGP8Advertisement, int]:
    """Helper: build a BGP8Advertisement and compute its CF value.

    Returns (advertisement, cf_value).
    """
    cf_value = 0
    if cf_components is not None:
        cf_value = compute_cf(cf_components)

    adv = BGP8Advertisement(
        prefix=prefix,
        origin_asn=origin_asn,
        as_path=as_path,
        next_hop=next_hop,
        cf_accumulated=cf_value / 0xFFFFFFFF,
        prefix_length=prefix_length,
    )
    return adv, cf_value
