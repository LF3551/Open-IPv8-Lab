# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for BGP8 path selection with CF metric."""

from __future__ import annotations

from ipv8lab.bgp8_selection import (
    BGP8PathSelector,
    BGPinVRFPropagator,
    CapabilitySet,
    LargeCommPropagator,
    NativeBGP8Propagator,
    PathCandidate,
    PropagationMechanism,
    Route8,
    Route8RIB,
    SelectionResult,
    build_advertisement,
    decode_rn_from_community,
    encode_large_community,
    negotiate_mechanism,
)
from ipv8lab.companions import BGP8Advertisement, BGP8Peer, BGP8State
from ipv8lab.cost_factor import CFComponents, compute_cf


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _adv(
    prefix: str = "64496-0.0.0.0/8",
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
        assert s.candidate_count("64496-0.0.0.0/8") == 2

    def test_withdraw(self) -> None:
        s = BGP8PathSelector(local_asn=64500)
        s.receive_advertisement(_adv(origin=64496, as_path=(64496,)))
        ok = s.withdraw("64496-0.0.0.0/8", 64496)
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
        result = s.select("64496-0.0.0.0/8")
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
        result = s.select("64496-0.0.0.0/8")
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
        result = s.select("64496-0.0.0.0/8")
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
        assert s.select("64496-0.0.0.0/8").best is not None
        assert s.select("64496-0.0.0.0/8").best.advertisement.next_hop == "peer-a"  # type: ignore[union-attr]

        # Intrazone CF doesn't change relative order (adds equally)
        s.intrazone_cf = 50
        assert s.select("64496-0.0.0.0/8").best.advertisement.next_hop == "peer-a"  # type: ignore[union-attr]

    def test_select_all(self) -> None:
        s = BGP8PathSelector(local_asn=64500)
        s.receive_advertisement(
            _adv(prefix="64496-0.0.0.0/8", origin=64496, as_path=(64496,)),
            hop_cfs=(100,),
        )
        s.receive_advertisement(
            _adv(prefix="64497-0.0.0.0/8", origin=64497, as_path=(64497,)),
            hop_cfs=(200,),
        )
        results = s.select_all()
        assert len(results) == 2
        assert all(r.best is not None for r in results.values())

    def test_best_path_shortcut(self) -> None:
        s = BGP8PathSelector(local_asn=64500)
        s.receive_advertisement(_adv(as_path=(64496,)), hop_cfs=(100,))
        assert s.best_path("64496-0.0.0.0/8") is not None

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

        best = s.best_path("64496-0.0.0.0/8")
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
        best = s.best_path("64496-0.0.0.0/8")
        assert best is not None
        assert best.accumulated_cf == hop1 + hop2 + hop3

    def test_cf_saturating(self) -> None:
        """CF accumulation saturates at 2^32 - 1."""
        s = BGP8PathSelector(local_asn=64500)
        s.receive_advertisement(
            _adv(origin=64496, as_path=(64496,)),
            hop_cfs=(0xFFFFFFFF, 1),
        )
        best = s.best_path("64496-0.0.0.0/8")
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
        result = s.select("64496-0.0.0.0/8")
        assert result.has_anomalies is True
        assert result.best is not None
        assert result.best.anomaly is True

    def test_build_advertisement_helper(self) -> None:
        components = CFComponents(rtt=0.2, packet_loss=0.1)
        adv, cf_val = build_advertisement(
            prefix="64496-0.0.0.0/8",
            origin_asn=64496,
            as_path=(64496,),
            cf_components=components,
        )
        assert adv.prefix == "64496-0.0.0.0/8"
        assert cf_val == compute_cf(components)
        assert cf_val > 0

    def test_build_advertisement_no_cf(self) -> None:
        adv, cf_val = build_advertisement(
            prefix="64496-0.0.0.0/8",
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

        result = sel.select("64496-0.0.0.0/8")
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
        assert sel.best_path("64496-0.0.0.0/8").advertisement.next_hop == "primary"  # type: ignore[union-attr]

        # Withdraw primary
        sel.withdraw("64496-0.0.0.0/8", 64496)

        # Backup takes over
        best = sel.best_path("64496-0.0.0.0/8")
        assert best is not None
        assert best.advertisement.next_hop == "backup"


# ===========================================================================
# Step 10 — Inter-AS propagation mechanisms
# ===========================================================================

def _adv10(prefix="64496-0.0.0.0/8", origin=64496, as_path=(64497, 64496),
         next_hop="64497-10.0.0.1", cf=0.0):
    return BGP8Advertisement(
        prefix=prefix, origin_asn=origin, as_path=as_path,
        next_hop=next_hop, cf_accumulated=cf, prefix_length=8,
    )


class TestPropagationMechanism:
    def test_three_values(self):
        assert len(PropagationMechanism) == 3

    def test_native_is_1(self):
        assert PropagationMechanism.NATIVE_BGP8 == 1

    def test_bgp_in_vrf_is_2(self):
        assert PropagationMechanism.BGP_IN_VRF == 2

    def test_large_community_is_3(self):
        assert PropagationMechanism.LARGE_COMMUNITY == 3


class TestCapabilityNegotiation:
    def test_native_wins(self):
        local = CapabilitySet(native_bgp8=True, bgp_in_vrf=True, large_community=True)
        remote = CapabilitySet(native_bgp8=True, bgp_in_vrf=True, large_community=True)
        assert negotiate_mechanism(local, remote) == PropagationMechanism.NATIVE_BGP8

    def test_vrf_wins_when_no_native(self):
        local = CapabilitySet(bgp_in_vrf=True, large_community=True)
        remote = CapabilitySet(bgp_in_vrf=True, large_community=True)
        assert negotiate_mechanism(local, remote) == PropagationMechanism.BGP_IN_VRF

    def test_large_comm_fallback(self):
        local = CapabilitySet(large_community=True)
        remote = CapabilitySet(native_bgp8=True, large_community=True)
        assert negotiate_mechanism(local, remote) == PropagationMechanism.LARGE_COMMUNITY

    def test_no_common_returns_none(self):
        local = CapabilitySet(native_bgp8=True)
        remote = CapabilitySet(bgp_in_vrf=True)
        assert negotiate_mechanism(local, remote) is None

    def test_native_requires_both_sides(self):
        local = CapabilitySet(native_bgp8=True)
        remote = CapabilitySet(native_bgp8=False, bgp_in_vrf=True)
        result = negotiate_mechanism(local, remote)
        assert result != PropagationMechanism.NATIVE_BGP8


class TestNativeBGP8Propagator:
    def test_produces_route8(self):
        p = NativeBGP8Propagator()
        route = p.to_route8(_adv10(), rn=64496)
        assert isinstance(route, Route8)
        assert route.mechanism == PropagationMechanism.NATIVE_BGP8

    def test_rn_preserved(self):
        p = NativeBGP8Propagator()
        route = p.to_route8(_adv10(), rn=64496)
        assert route.rn == 64496

    def test_prefix_preserved(self):
        p = NativeBGP8Propagator()
        route = p.to_route8(_adv10(prefix="64497-0.0.0.0/8"), rn=64497)
        assert route.prefix == "64497-0.0.0.0/8"

    def test_as_path_preserved(self):
        p = NativeBGP8Propagator()
        route = p.to_route8(_adv10(as_path=(64498, 64497, 64496)), rn=64496)
        assert route.as_path == (64498, 64497, 64496)


class TestBGPinVRFPropagator:
    def test_produces_route8_bgp_in_vrf(self):
        p = BGPinVRFPropagator()
        route = p.to_route8(_adv10(), rn=64496)
        assert route.mechanism == PropagationMechanism.BGP_IN_VRF

    def test_vrf_name_set(self):
        p = BGPinVRFPropagator()
        route = p.to_route8(_adv10(), rn=64496)
        assert route.vrf_name == "ipv8-asn-64496"

    def test_vrf_name_uses_rn(self):
        p = BGPinVRFPropagator()
        route = p.to_route8(_adv10(), rn=65000)
        assert "65000" in route.vrf_name


class TestLargeCommPropagator:
    def test_produces_route8_large_comm(self):
        p = LargeCommPropagator(local_asn=64497)
        route = p.to_route8(_adv10(), rn=64496)
        assert route.mechanism == PropagationMechanism.LARGE_COMMUNITY

    def test_community_set(self):
        p = LargeCommPropagator(local_asn=64497)
        route = p.to_route8(_adv10(), rn=64496)
        assert route.large_community is not None
        assert route.large_community == (64497, 64496, 0)

    def test_rn_recoverable_from_community(self):
        p = LargeCommPropagator(local_asn=64497)
        route = p.to_route8(_adv10(), rn=64496)
        assert decode_rn_from_community(route.large_community) == 64496


class TestRoute8Equivalence:
    """All three mechanisms must produce functionally identical Route8 entries."""

    def _routes(self, rn=64496):
        adv = _adv10(cf=0.5)
        n = NativeBGP8Propagator().to_route8(adv, rn)
        v = BGPinVRFPropagator().to_route8(adv, rn)
        lc = LargeCommPropagator(64497).to_route8(adv, rn)
        return n, v, lc

    def test_native_and_vrf_equivalent(self):
        n, v, _ = self._routes()
        assert n.equivalent_to(v)

    def test_native_and_large_comm_equivalent(self):
        n, _, lc = self._routes()
        assert n.equivalent_to(lc)

    def test_vrf_and_large_comm_equivalent(self):
        _, v, lc = self._routes()
        assert v.equivalent_to(lc)

    def test_different_cf_not_equivalent(self):
        adv1 = _adv10(cf=0.1)
        adv2 = _adv10(cf=0.9)
        r1 = NativeBGP8Propagator().to_route8(adv1, 64496)
        r2 = NativeBGP8Propagator().to_route8(adv2, 64496)
        assert not r1.equivalent_to(r2)


class TestRoute8RIB:
    def test_install_and_lookup(self):
        rib = Route8RIB()
        p = NativeBGP8Propagator()
        route = p.to_route8(_adv10(), rn=64496)
        rib.install(route)
        assert rib.lookup("64496-0.0.0.0/8", 64496) is not None

    def test_lower_cf_replaces_existing(self):
        rib = Route8RIB()
        adv_high = _adv10(cf=0.9)
        adv_low = _adv10(cf=0.1)
        p = NativeBGP8Propagator()
        rib.install(p.to_route8(adv_high, 64496))
        rib.install(p.to_route8(adv_low, 64496))
        r = rib.lookup("64496-0.0.0.0/8", 64496)
        assert r.cf_accumulated < int(0.5 * 0xFFFFFFFF)

    def test_higher_cf_does_not_replace(self):
        rib = Route8RIB()
        adv_low = _adv10(cf=0.1)
        adv_high = _adv10(cf=0.9)
        p = NativeBGP8Propagator()
        rib.install(p.to_route8(adv_low, 64496))
        result = rib.install(p.to_route8(adv_high, 64496))
        assert result is False

    def test_remove(self):
        rib = Route8RIB()
        p = NativeBGP8Propagator()
        rib.install(p.to_route8(_adv10(), rn=64496))
        assert rib.remove("64496-0.0.0.0/8", 64496)
        assert rib.lookup("64496-0.0.0.0/8", 64496) is None

    def test_size(self):
        rib = Route8RIB()
        p = NativeBGP8Propagator()
        rib.install(p.to_route8(_adv10(prefix="64496-0.0.0.0/8"), rn=64496))
        rib.install(p.to_route8(_adv10(prefix="64497-0.0.0.0/8"), rn=64497))
        assert rib.size == 2

    def test_prefixes(self):
        rib = Route8RIB()
        p = NativeBGP8Propagator()
        rib.install(p.to_route8(_adv10(prefix="64496-0.0.0.0/8"), rn=64496))
        rib.install(p.to_route8(_adv10(prefix="64497-0.0.0.0/8"), rn=64497))
        assert set(rib.prefixes()) == {"64496-0.0.0.0/8", "64497-0.0.0.0/8"}

    def test_all_three_mechanisms_install(self):
        rib = Route8RIB()
        adv = _adv10(cf=0.5)
        rn = 64496
        rib.install(NativeBGP8Propagator().to_route8(adv, rn))
        # Same prefix+rn, slightly better CF from VRF mechanism
        adv2 = _adv10(cf=0.2)
        rib.install(BGPinVRFPropagator().to_route8(adv2, rn))
        r = rib.lookup("64496-0.0.0.0/8", 64496)
        assert r.mechanism == PropagationMechanism.BGP_IN_VRF


class TestLargeCommunityHelpers:
    def test_encode(self):
        assert encode_large_community(64497, 64496) == (64497, 64496, 0)

    def test_decode(self):
        assert decode_rn_from_community((64497, 64496, 0)) == 64496

    def test_roundtrip(self):
        comm = encode_large_community(65000, 12345)
        assert decode_rn_from_community(comm) == 12345
