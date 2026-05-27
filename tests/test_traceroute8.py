# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for Traceroute8 module."""

from __future__ import annotations

from ipv8lab.address import IPv8Address
from ipv8lab.icmpv8 import ICMPv8Type
from ipv8lab.traceroute8 import (
    Hop,
    Router,
    Topology,
    TracerouteResult,
    _simulated_rtt,
    build_diamond_topology,
    build_linear_topology,
    build_loop_topology,
    build_multi_path_topology,
    traceroute,
)


# ---------------------------------------------------------------------------
# Topology
# ---------------------------------------------------------------------------

class TestTopology:
    def test_add_router(self) -> None:
        topo = Topology()
        r = topo.add_router("R0", "64496-10.0.0.1")
        assert r.name == "R0"
        assert topo.router_count == 1

    def test_add_router_with_routes(self) -> None:
        topo = Topology()
        r = topo.add_router("R0", "64496-10.0.0.1", {"*": "R1"})
        assert r.lookup(IPv8Address.parse("64497-10.0.0.1")) == "R1"

    def test_get_router(self) -> None:
        topo = Topology()
        topo.add_router("R0", "64496-10.0.0.1")
        assert topo.get_router("R0") is not None
        assert topo.get_router("R999") is None

    def test_router_count(self) -> None:
        topo = Topology()
        assert topo.router_count == 0
        topo.add_router("R0", "64496-10.0.0.1")
        topo.add_router("R1", "64497-10.0.0.1")
        assert topo.router_count == 2


class TestRouter:
    def test_lookup_exact(self) -> None:
        prefix = IPv8Address.parse("64497-10.0.0.1").prefix_str
        r = Router("R0", IPv8Address.parse("64496-10.0.0.1"), {prefix: "R1"})
        assert r.lookup(IPv8Address.parse("64497-10.0.0.1")) == "R1"

    def test_lookup_default(self) -> None:
        r = Router("R0", IPv8Address.parse("64496-10.0.0.1"), {"*": "R1"})
        assert r.lookup(IPv8Address.parse("64500-10.0.0.1")) == "R1"

    def test_lookup_none(self) -> None:
        r = Router("R0", IPv8Address.parse("64496-10.0.0.1"))
        assert r.lookup(IPv8Address.parse("64500-10.0.0.1")) is None

    def test_lookup_specific_over_default(self) -> None:
        prefix = IPv8Address.parse("64497-10.0.0.1").prefix_str
        r = Router("R0", IPv8Address.parse("64496-10.0.0.1"), {prefix: "R2", "*": "R1"})
        assert r.lookup(IPv8Address.parse("64497-10.0.0.1")) == "R2"
        assert r.lookup(IPv8Address.parse("64500-10.0.0.1")) == "R1"


# ---------------------------------------------------------------------------
# TracerouteResult
# ---------------------------------------------------------------------------

class TestTracerouteResult:
    def test_to_dict(self) -> None:
        result = TracerouteResult(
            src=IPv8Address.parse("64496-10.0.0.1"),
            dst=IPv8Address.parse("64497-10.0.0.1"),
            completed=True,
        )
        result.hops.append(Hop(
            ttl=1, address=IPv8Address.parse("64497-10.0.0.1"),
            router_name="R1", rtt_ms=1.5,
            icmp_type=ICMPv8Type.ECHO_REPLY, reached=True,
        ))
        d = result.to_dict()
        assert d["completed"] is True
        assert d["hop_count"] == 1
        assert d["hops"][0]["reached"] is True

    def test_path_addresses(self) -> None:
        result = TracerouteResult(
            src=IPv8Address.parse("64496-10.0.0.1"),
            dst=IPv8Address.parse("64498-10.0.0.1"),
        )
        result.hops.append(Hop(
            ttl=1, address=IPv8Address.parse("64497-10.0.0.1"),
            router_name="R1", rtt_ms=1.0,
            icmp_type=ICMPv8Type.TIME_EXCEEDED,
        ))
        result.hops.append(Hop(
            ttl=2, address=IPv8Address.parse("64498-10.0.0.1"),
            router_name="R2", rtt_ms=2.0,
            icmp_type=ICMPv8Type.ECHO_REPLY, reached=True,
        ))
        addrs = result.path_addresses()
        assert len(addrs) == 2


# ---------------------------------------------------------------------------
# Simulated RTT
# ---------------------------------------------------------------------------

class TestSimulatedRtt:
    def test_deterministic(self) -> None:
        a = _simulated_rtt("R0", 1)
        b = _simulated_rtt("R0", 1)
        assert a == b

    def test_varies_by_router(self) -> None:
        a = _simulated_rtt("R0", 1)
        b = _simulated_rtt("R1", 1)
        assert a != b

    def test_range(self) -> None:
        for i in range(20):
            rtt = _simulated_rtt(f"R{i}", i)
            assert 0.5 <= rtt <= 15.0


# ---------------------------------------------------------------------------
# Traceroute — linear
# ---------------------------------------------------------------------------

class TestTracerouteLinear:
    def test_linear_3_hops(self) -> None:
        topo, src, dst = build_linear_topology(3)
        result = traceroute(topo, src, dst)
        assert result.completed
        assert result.hop_count >= 2  # at least intermediate + destination

    def test_linear_5_hops(self) -> None:
        topo, src, dst = build_linear_topology(5)
        result = traceroute(topo, src, dst)
        assert result.completed
        assert result.hop_count == 4  # R1, R2, R3, R4 (R0=src, R4=dst)

    def test_linear_10_hops(self) -> None:
        topo, src, dst = build_linear_topology(10)
        result = traceroute(topo, src, dst)
        assert result.completed

    def test_final_hop_reached(self) -> None:
        topo, src, dst = build_linear_topology(3)
        result = traceroute(topo, src, dst)
        assert result.hops[-1].reached
        assert result.hops[-1].icmp_type == ICMPv8Type.ECHO_REPLY

    def test_intermediate_time_exceeded(self) -> None:
        topo, src, dst = build_linear_topology(5)
        result = traceroute(topo, src, dst)
        for hop in result.hops[:-1]:
            assert hop.icmp_type == ICMPv8Type.TIME_EXCEEDED
            assert not hop.reached

    def test_ttl_incrementing(self) -> None:
        topo, src, dst = build_linear_topology(5)
        result = traceroute(topo, src, dst)
        ttls = [h.ttl for h in result.hops]
        assert ttls == sorted(ttls)
        assert ttls[0] >= 1

    def test_single_hop(self) -> None:
        topo, src, dst = build_linear_topology(2)
        result = traceroute(topo, src, dst)
        assert result.completed
        assert result.hop_count >= 1


# ---------------------------------------------------------------------------
# Traceroute — diamond
# ---------------------------------------------------------------------------

class TestTracerouteDiamond:
    def test_diamond_completes(self) -> None:
        topo, src, dst = build_diamond_topology()
        result = traceroute(topo, src, dst)
        assert result.completed

    def test_diamond_path(self) -> None:
        topo, src, dst = build_diamond_topology()
        result = traceroute(topo, src, dst)
        # Default route R0→R1→R3
        router_names = [h.router_name for h in result.hops]
        assert "R1" in router_names
        assert "R3" in router_names

    def test_diamond_hop_count(self) -> None:
        topo, src, dst = build_diamond_topology()
        result = traceroute(topo, src, dst)
        assert result.hop_count == 2  # R1, R3


# ---------------------------------------------------------------------------
# Traceroute — loop
# ---------------------------------------------------------------------------

class TestTracerouteLoop:
    def test_loop_detected(self) -> None:
        topo, src, dst = build_loop_topology()
        result = traceroute(topo, src, dst)
        assert not result.completed
        assert result.error is not None
        assert "loop" in result.error.lower()


# ---------------------------------------------------------------------------
# Traceroute — multi-path
# ---------------------------------------------------------------------------

class TestTracerouteMultiPath:
    def test_multipath_completes(self) -> None:
        topo, src, dst = build_multi_path_topology()
        result = traceroute(topo, src, dst)
        assert result.completed

    def test_multipath_uses_specific_route(self) -> None:
        topo, src, dst = build_multi_path_topology()
        result = traceroute(topo, src, dst)
        router_names = [h.router_name for h in result.hops]
        # R0 routes 64499 prefix via R2, not R1
        assert "R2" in router_names


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_src_is_dst(self) -> None:
        topo = Topology()
        topo.add_router("R0", "64496-10.0.0.1")
        addr = topo.routers["R0"].address
        result = traceroute(topo, addr, addr)
        assert result.completed
        assert result.hop_count == 1

    def test_max_hops_limit(self) -> None:
        topo, src, dst = build_linear_topology(50)
        result = traceroute(topo, src, dst, max_hops=3)
        assert not result.completed
        assert result.hop_count == 3

    def test_empty_topology(self) -> None:
        topo = Topology()
        src = IPv8Address.parse("64496-10.0.0.1")
        dst = IPv8Address.parse("64497-10.0.0.1")
        result = traceroute(topo, src, dst)
        assert not result.completed
        assert result.error is not None

    def test_no_route_at_router(self) -> None:
        topo = Topology()
        topo.add_router("R0", "64496-10.0.0.1")  # no routes
        src = topo.routers["R0"].address
        dst = IPv8Address.parse("64500-10.0.0.1")
        result = traceroute(topo, src, dst)
        assert not result.completed

    def test_string_addresses(self) -> None:
        topo, _, _ = build_linear_topology(3)
        result = traceroute(topo, "64496-10.0.0.1", "64498-10.0.0.1")
        assert result.completed

    def test_start_ttl(self) -> None:
        topo, src, dst = build_linear_topology(5)
        result = traceroute(topo, src, dst, start_ttl=3)
        assert result.hops[0].ttl == 3

    def test_rtt_positive(self) -> None:
        topo, src, dst = build_linear_topology(5)
        result = traceroute(topo, src, dst)
        for hop in result.hops:
            assert hop.rtt_ms > 0


# ---------------------------------------------------------------------------
# Pre-built topology builders
# ---------------------------------------------------------------------------

class TestBuilders:
    def test_build_linear(self) -> None:
        topo, src, dst = build_linear_topology(3)
        assert topo.router_count == 3
        assert src != dst

    def test_build_diamond(self) -> None:
        topo, src, dst = build_diamond_topology()
        assert topo.router_count == 4

    def test_build_loop(self) -> None:
        topo, src, dst = build_loop_topology()
        assert topo.router_count == 3

    def test_build_multi_path(self) -> None:
        topo, src, dst = build_multi_path_topology()
        assert topo.router_count == 4
