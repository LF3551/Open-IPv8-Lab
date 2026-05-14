# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for BGP8 path selection with CF metric."""

from __future__ import annotations

from ipv8lab.bgp8_selection import (
    BGP8PathSelector,
    PathCandidate,
    SelectionResult,
    build_advertisement,
)
from ipv8lab.companions import BGP8Advertisement, BGP8Peer, BGP8State
from ipv8lab.cost_factor import CFComponents, compute_cf


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _adv(
    prefix: str = "64496.0.0.0.0/8",
    origin: int = 64496,
    as_path: tuple[int, ...] = (64496,),
    next_hop: str = "peer-1",
    prefix_length: int = 8,
) -> BGP8Advertisement:
    return BGP8Advertisement(
        prefix=prefix,
        origin_asn=origin,
        as_path=as_path,
        next_hop=next_hop,
        prefix_length=prefix_length,
    )


# ---------------------------------------------------------------------------
# PathCandidate
# ---------------------------------------------------------------------------

class TestPathCandidate:
    def test_accumulated_cf(self) -> None:
        c = PathCandidate(advertisement=_adv(), hop_cfs=(100, 200, 300))
        assert c.accumulated_cf == 600

    def test_accumulated_cf_empty(self) -> None:
        c = PathCandidate(advertisement=_adv(), hop_cfs=())
        assert c.accumulated_cf == 0

    def test_as_path_length(self) -> None:
        c = PathCandidate(advertisement=_adv(as_path=(64496, 64497, 64498)))
        assert c.as_path_length == 3

    def test_no_anomaly_no_distance(self) -> None:
        c = PathCandidate(advertisement=_adv(), distance_km=0.0, measured_rtt_ms=1.0)
        assert c.anomaly is False

    def test_anomaly_detected(self) -> None:
        # 10000 km → physics floor ~50ms one-way → ~100ms RTT
        c = PathCandidate(
            advertisement=_adv(),
            distance_km=10000.0,
            measured_rtt_ms=10.0,  # impossibly fast
        )
        assert c.anomaly is True

    def test_no_anomaly_valid_rtt(self) -> None:
        c = PathCandidate(
            advertisement=_adv(),
            distance_km=1000.0,
            measured_rtt_ms=50.0,  # reasonable
        )
        assert c.anomaly is False


# ---------------------------------------------------------------------------
# SelectionResult
# ---------------------------------------------------------------------------

class TestSelectionResult:
    def test_has_anomalies(self) -> None:
        c = PathCandidate(
            advertisement=_adv(), distance_km=10000, measured_rtt_ms=1.0,
        )
        r = SelectionResult(best=c, candidates=(c,))
        assert r.has_anomalies is True

    def test_no_anomalies(self) -> None:
        c = PathCandidate(advertisement=_adv())
        r = SelectionResult(best=c, candidates=(c,))
        assert r.has_anomalies is False


# ---------------------------------------------------------------------------
# BGP8PathSelector — basics
# ---------------------------------------------------------------------------

class TestSelectorBasics:
    def test_local_asn(self) -> None:
        s = BGP8PathSelector(local_asn=64496)
        assert s.local_asn == 64496

    def test_add_peer(self) -> None:
        s = BGP8PathSelector(local_asn=64496)
        p = BGP8Peer(asn=64497, address="127.1.0.0.10.0.1.1")
        s.add_peer(p)
        assert s.peer_count == 1
        assert s.get_peer(64497) is p

    def test_get_peer_missing(self) -> None:
        s = BGP8PathSelector(local_asn=64496)
        assert s.get_peer(99999) is None

    def test_rib_empty(self) -> None:
        s = BGP8PathSelector(local_asn=64496)
        assert s.rib_size() == 0
        assert s.known_prefixes() == []

    def test_clear(self) -> None:
        s = BGP8PathSelector(local_asn=64496)
        s.receive_advertisement(_adv())
        s.clear()
        assert s.rib_size() == 0


# ---------------------------------------------------------------------------
# Receive advertisements
# ---------------------------------------------------------------------------

class TestReceiveAdvertisement:
    def test_receive_valid(self) -> None:
        s = BGP8PathSelector(local_asn=64500)
        ok = s.receive_advertisement(_adv(as_path=(64496,)), hop_cfs=(100,))
        assert ok is True
        assert s.rib_size() == 1

    def test_reject_invalid_prefix(self) -> None:
        s = BGP8PathSelector(local_asn=64500)
        adv = _adv(prefix_length=24)  # /24 violates /16 minimum
        ok = s.receive_advertisement(adv)
        assert ok is False
        assert s.rib_size() == 0

    def test_reject_as_path_loop(self) -> None:
        s = BGP8PathSelector(local_asn=64496)
        adv = _adv(as_path=(64497, 64496))  # local ASN in path
        ok = s.receive_advertisement(adv)
        assert ok is False

    def test_multiple_candidates(self) -> None:
        s = BGP8PathSelector(local_asn=64500)
        s.receive_advertisement(
            _adv(origin=64496, as_path=(64496,), next_hop="peer-a"),
            hop_cfs=(1000,),
        )
        s.receive_advertisement(
            _adv(origin=64497, as_path=(64497, 64496), next_hop="peer-b"),
            hop_cfs=(500, 500),
        )
        assert s.candidate_count("64496.0.0.0.0/8") == 2

    def test_withdraw(self) -> None:
        s = BGP8PathSelector(local_asn=64500)
        s.receive_advertisement(_adv(origin=64496, as_path=(64496,)))
        ok = s.withdraw("64496.0.0.0.0/8", 64496)
        assert ok is True
        assert s.rib_size() == 0

    def test_withdraw_nonexistent(self) -> None:
        s = BGP8PathSelector(local_asn=64500)
        ok = s.withdraw("no-such-prefix/8", 64496)
        assert ok is False


# ---------------------------------------------------------------------------
# Path selection — CF-based
# ---------------------------------------------------------------------------

class TestPathSelection:
    def test_select_lowest_cf(self) -> None:
        s = BGP8PathSelector(local_asn=64500)
        # Path A: high CF
        s.receive_advertisement(
            _adv(origin=64496, as_path=(64496,), next_hop="peer-a"),
            hop_cfs=(5000,),
        )
        # Path B: low CF
        s.receive_advertisement(
            _adv(origin=64497, as_path=(64497, 64496), next_hop="peer-b"),
            hop_cfs=(100, 100),
        )
        result = s.select("64496.0.0.0.0/8")
        assert result.best is not None
        assert result.best.advertisement.next_hop == "peer-b"
        assert result.best.accumulated_cf == 200

    def test_select_empty_prefix(self) -> None:
        s = BGP8PathSelector(local_asn=64500)
        result = s.select("no-such/8")
        assert result.best is None
        assert result.reason == "no paths"

    def test_tiebreak_shortest_as_path(self) -> None:
        s = BGP8PathSelector(local_asn=64500)
        # Same CF, different AS-path lengths
        s.receive_advertisement(
            _adv(origin=64496, as_path=(64496,), next_hop="direct"),
            hop_cfs=(1000,),
        )
        s.receive_advertisement(
            _adv(origin=64497, as_path=(64497, 64496), next_hop="indirect"),
            hop_cfs=(500, 500),
        )
        result = s.select("64496.0.0.0.0/8")
        assert result.best is not None
        # Both have CF=1000; direct has shorter AS-path
        assert result.best.advertisement.next_hop == "direct"
        assert result.best.as_path_length == 1

    def test_tiebreak_lowest_origin_asn(self) -> None:
        s = BGP8PathSelector(local_asn=64500)
        # Same CF, same AS-path length, different origin ASN
        s.receive_advertisement(
            _adv(origin=64497, as_path=(64497,), next_hop="peer-b"),
            hop_cfs=(1000,),
        )
        s.receive_advertisement(
            _adv(origin=64496, as_path=(64496,), next_hop="peer-a"),
            hop_cfs=(1000,),
        )
        result = s.select("64496.0.0.0.0/8")
        assert result.best is not None
        assert result.best.advertisement.origin_asn == 64496

    def test_intrazone_cf_shifts_selection(self) -> None:
        s = BGP8PathSelector(local_asn=64500)
        # Path A: low external CF
        s.receive_advertisement(
            _adv(origin=64496, as_path=(64496,), next_hop="peer-a"),
            hop_cfs=(100,),
        )
        # Path B: slightly higher external CF
        s.receive_advertisement(
            _adv(origin=64497, as_path=(64497,), next_hop="peer-b"),
            hop_cfs=(200,),
        )
        # Without intrazone, A wins
        assert s.select("64496.0.0.0.0/8").best is not None
        assert s.select("64496.0.0.0.0/8").best.advertisement.next_hop == "peer-a"  # type: ignore[union-attr]

        # Intrazone CF doesn't change relative order (adds equally)
        s.intrazone_cf = 50
        assert s.select("64496.0.0.0.0/8").best.advertisement.next_hop == "peer-a"  # type: ignore[union-attr]

    def test_select_all(self) -> None:
        s = BGP8PathSelector(local_asn=64500)
        s.receive_advertisement(
            _adv(prefix="64496.0.0.0.0/8", origin=64496, as_path=(64496,)),
            hop_cfs=(100,),
        )
        s.receive_advertisement(
            _adv(prefix="64497.0.0.0.0/8", origin=64497, as_path=(64497,)),
            hop_cfs=(200,),
        )
        results = s.select_all()
        assert len(results) == 2
        assert all(r.best is not None for r in results.values())

    def test_best_path_shortcut(self) -> None:
        s = BGP8PathSelector(local_asn=64500)
        s.receive_advertisement(_adv(as_path=(64496,)), hop_cfs=(100,))
        assert s.best_path("64496.0.0.0.0/8") is not None

    def test_best_path_none(self) -> None:
        s = BGP8PathSelector(local_asn=64500)
        assert s.best_path("no-such/8") is None


# ---------------------------------------------------------------------------
# CF integration
# ---------------------------------------------------------------------------

class TestCFIntegration:
    def test_compute_cf_and_select(self) -> None:
        """Build advertisements from CFComponents and select best."""
        s = BGP8PathSelector(local_asn=64500)

        # Path A: good link
        cf_a = compute_cf(CFComponents(rtt=0.1, packet_loss=0.05))
        s.receive_advertisement(
            _adv(origin=64496, as_path=(64496,), next_hop="good-link"),
            hop_cfs=(cf_a,),
        )

        # Path B: bad link (high loss + congestion)
        cf_b = compute_cf(CFComponents(rtt=0.5, packet_loss=0.3, congestion=0.6))
        s.receive_advertisement(
            _adv(origin=64497, as_path=(64497,), next_hop="bad-link"),
            hop_cfs=(cf_b,),
        )

        best = s.best_path("64496.0.0.0.0/8")
        assert best is not None
        assert best.advertisement.next_hop == "good-link"
        assert best.accumulated_cf < cf_b

    def test_multi_hop_accumulation(self) -> None:
        """CF accumulates across multiple AS hops."""
        s = BGP8PathSelector(local_asn=64500)

        # 3-hop path: each hop has CF
        hop1 = compute_cf(CFComponents(rtt=0.1))
        hop2 = compute_cf(CFComponents(rtt=0.2))
        hop3 = compute_cf(CFComponents(rtt=0.15))

        s.receive_advertisement(
            _adv(origin=64496, as_path=(64498, 64497, 64496), next_hop="transit"),
            hop_cfs=(hop1, hop2, hop3),
        )
        best = s.best_path("64496.0.0.0.0/8")
        assert best is not None
        assert best.accumulated_cf == hop1 + hop2 + hop3

    def test_cf_saturating(self) -> None:
        """CF accumulation saturates at 2^32 - 1."""
        s = BGP8PathSelector(local_asn=64500)
        s.receive_advertisement(
            _adv(origin=64496, as_path=(64496,)),
            hop_cfs=(0xFFFFFFFF, 1),
        )
        best = s.best_path("64496.0.0.0.0/8")
        assert best is not None
        assert best.accumulated_cf == 0xFFFFFFFF

    def test_anomaly_flagged(self) -> None:
        """CF anomaly flagged when RTT < physics floor."""
        s = BGP8PathSelector(local_asn=64500)
        s.receive_advertisement(
            _adv(origin=64496, as_path=(64496,)),
            hop_cfs=(100,),
            distance_km=10000.0,
            measured_rtt_ms=5.0,  # impossibly fast
        )
        result = s.select("64496.0.0.0.0/8")
        assert result.has_anomalies is True
        assert result.best is not None
        assert result.best.anomaly is True

    def test_build_advertisement_helper(self) -> None:
        components = CFComponents(rtt=0.2, packet_loss=0.1)
        adv, cf_val = build_advertisement(
            prefix="64496.0.0.0.0/8",
            origin_asn=64496,
            as_path=(64496,),
            cf_components=components,
        )
        assert adv.prefix == "64496.0.0.0.0/8"
        assert cf_val == compute_cf(components)
        assert cf_val > 0

    def test_build_advertisement_no_cf(self) -> None:
        adv, cf_val = build_advertisement(
            prefix="64496.0.0.0.0/8",
            origin_asn=64496,
            as_path=(64496,),
        )
        assert cf_val == 0


# ---------------------------------------------------------------------------
# Intrazone CF
# ---------------------------------------------------------------------------

class TestIntrazoneCF:
    def test_default_zero(self) -> None:
        s = BGP8PathSelector(local_asn=64500)
        assert s.intrazone_cf == 0

    def test_set_intrazone(self) -> None:
        s = BGP8PathSelector(local_asn=64500)
        s.intrazone_cf = 500
        assert s.intrazone_cf == 500

    def test_clamp_negative(self) -> None:
        s = BGP8PathSelector(local_asn=64500)
        s.intrazone_cf = -10
        assert s.intrazone_cf == 0

    def test_clamp_overflow(self) -> None:
        s = BGP8PathSelector(local_asn=64500)
        s.intrazone_cf = 0x1FFFFFFFF
        assert s.intrazone_cf == 0xFFFFFFFF


# ---------------------------------------------------------------------------
# Realistic scenario
# ---------------------------------------------------------------------------

class TestRealisticScenario:
    def test_three_upstream_selection(self) -> None:
        """AS 64500 has three upstreams — select by CF."""
        sel = BGP8PathSelector(local_asn=64500)

        # Upstream A: direct peering, low CF
        sel.add_peer(BGP8Peer(
            asn=64496, address="peer-a", state=BGP8State.ESTABLISHED,
        ))
        sel.receive_advertisement(
            _adv(origin=64496, as_path=(64496,), next_hop="peer-a"),
            hop_cfs=(compute_cf(CFComponents(rtt=0.05, packet_loss=0.01)),),
        )

        # Upstream B: transit via 64497, moderate CF
        sel.add_peer(BGP8Peer(
            asn=64497, address="peer-b", state=BGP8State.ESTABLISHED,
        ))
        sel.receive_advertisement(
            _adv(origin=64496, as_path=(64497, 64496), next_hop="peer-b"),
            hop_cfs=(
                compute_cf(CFComponents(rtt=0.15, packet_loss=0.05)),
                compute_cf(CFComponents(rtt=0.10, packet_loss=0.02)),
            ),
        )

        # Upstream C: transit via 64498+64499, high CF
        sel.add_peer(BGP8Peer(
            asn=64498, address="peer-c", state=BGP8State.ESTABLISHED,
        ))
        sel.receive_advertisement(
            _adv(origin=64496, as_path=(64498, 64499, 64496), next_hop="peer-c"),
            hop_cfs=(
                compute_cf(CFComponents(rtt=0.3, packet_loss=0.1, congestion=0.2)),
                compute_cf(CFComponents(rtt=0.25, packet_loss=0.08)),
                compute_cf(CFComponents(rtt=0.2, packet_loss=0.05)),
            ),
        )

        result = sel.select("64496.0.0.0.0/8")
        assert result.best is not None
        assert result.best.advertisement.next_hop == "peer-a"
        assert result.reason == "lowest CF"
        assert len(result.candidates) == 3

    def test_failover_on_withdraw(self) -> None:
        """When best path is withdrawn, second-best becomes best."""
        sel = BGP8PathSelector(local_asn=64500)

        # Install two paths
        sel.receive_advertisement(
            _adv(origin=64496, as_path=(64496,), next_hop="primary"),
            hop_cfs=(100,),
        )
        sel.receive_advertisement(
            _adv(origin=64497, as_path=(64497, 64496), next_hop="backup"),
            hop_cfs=(200, 200),
        )

        # Primary wins
        assert sel.best_path("64496.0.0.0.0/8").advertisement.next_hop == "primary"  # type: ignore[union-attr]

        # Withdraw primary
        sel.withdraw("64496.0.0.0.0/8", 64496)

        # Backup takes over
        best = sel.best_path("64496.0.0.0.0/8")
        assert best is not None
        assert best.advertisement.next_hop == "backup"
