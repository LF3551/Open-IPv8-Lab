# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for CF performance dashboard module."""

from __future__ import annotations

from ipv8lab.cf_dashboard import CFDashboardState, create_demo_state
from ipv8lab.cost_factor import CFComponents


# ---------------------------------------------------------------------------
# PathEntry
# ---------------------------------------------------------------------------

class TestPathEntry:
    def test_to_dict(self) -> None:
        state = CFDashboardState()
        entry = state.add_path(
            path_id="p1", origin_asn=64497, as_path=[64497],
            components=CFComponents(rtt=0.1),
        )
        d = entry.to_dict()
        assert d["path_id"] == "p1"
        assert d["origin_asn"] == 64497
        assert d["components"]["rtt"] == 0.1
        assert d["cf_value"] > 0

    def test_anomaly_detection(self) -> None:
        state = CFDashboardState()
        entry = state.add_path(
            path_id="anom", origin_asn=64500, as_path=[64500],
            components=CFComponents(rtt=0.01),
            distance_km=10000.0, measured_rtt_ms=5.0,
        )
        assert entry.anomaly is True

    def test_no_anomaly_no_distance(self) -> None:
        state = CFDashboardState()
        entry = state.add_path(
            path_id="ok", origin_asn=64497, as_path=[64497],
            components=CFComponents(rtt=0.1),
        )
        assert entry.anomaly is False

    def test_accumulated_cf_with_hop_cfs(self) -> None:
        state = CFDashboardState()
        entry = state.add_path(
            path_id="multi", origin_asn=64497, as_path=[64498, 64497],
            components=CFComponents(rtt=0.1),
            hop_cfs=[100, 200],
        )
        assert entry.accumulated_cf == 300


# ---------------------------------------------------------------------------
# CFDashboardState
# ---------------------------------------------------------------------------

class TestCFDashboardState:
    def test_add_and_get_path(self) -> None:
        state = CFDashboardState()
        state.add_path("p1", 64497, [64497], CFComponents(rtt=0.1))
        assert state.path_count == 1
        assert state.get_path("p1") is not None

    def test_remove_path(self) -> None:
        state = CFDashboardState()
        state.add_path("p1", 64497, [64497], CFComponents())
        assert state.remove_path("p1") is True
        assert state.path_count == 0

    def test_remove_nonexistent(self) -> None:
        state = CFDashboardState()
        assert state.remove_path("nope") is False

    def test_best_path(self) -> None:
        state = CFDashboardState()
        state.add_path("high", 64497, [64497], CFComponents(rtt=0.5, packet_loss=0.5))
        state.add_path("low", 64498, [64498], CFComponents(rtt=0.01))
        best = state.best_path()
        assert best is not None
        assert best.path_id == "low"

    def test_best_path_empty(self) -> None:
        state = CFDashboardState()
        assert state.best_path() is None

    def test_ranked_paths(self) -> None:
        state = CFDashboardState()
        state.add_path("c", 64499, [64499], CFComponents(rtt=0.5))
        state.add_path("a", 64497, [64497], CFComponents(rtt=0.1))
        state.add_path("b", 64498, [64498], CFComponents(rtt=0.3))
        ranked = state.ranked_paths()
        assert [p.path_id for p in ranked] == ["a", "b", "c"]

    def test_anomalies(self) -> None:
        state = CFDashboardState()
        state.add_path("ok", 64497, [64497], CFComponents(), distance_km=100.0, measured_rtt_ms=10.0)
        state.add_path("bad", 64498, [64498], CFComponents(), distance_km=10000.0, measured_rtt_ms=1.0)
        assert len(state.anomalies()) == 1
        assert state.anomalies()[0].path_id == "bad"

    def test_intrazone_cf(self) -> None:
        state = CFDashboardState(intrazone_cf=500)
        assert state.intrazone_cf == 500
        state.intrazone_cf = 1000
        assert state.intrazone_cf == 1000

    def test_intrazone_cf_clamped(self) -> None:
        state = CFDashboardState()
        state.intrazone_cf = -1
        assert state.intrazone_cf == 0

    def test_summary(self) -> None:
        state = CFDashboardState(intrazone_cf=100)
        state.add_path("p1", 64497, [64497], CFComponents(rtt=0.1))
        s = state.summary()
        assert s["paths"] == 1
        assert s["best_path"] == "p1"
        assert s["intrazone_cf"] == 100

    def test_to_dict(self) -> None:
        state = CFDashboardState()
        state.add_path("p1", 64497, [64497], CFComponents(rtt=0.2))
        d = state.to_dict()
        assert "summary" in d
        assert "paths" in d
        assert len(d["paths"]) == 1

    def test_to_dict_with_benchmarks(self) -> None:
        state = CFDashboardState()
        state.run_benchmarks(iterations=10)
        d = state.to_dict()
        assert "benchmarks" in d
        assert len(d["benchmarks"]) == 6

    def test_clear(self) -> None:
        state = CFDashboardState()
        state.add_path("p1", 64497, [64497], CFComponents())
        state.run_benchmarks(iterations=10)
        state.clear()
        assert state.path_count == 0
        assert state.benchmarks is None

    def test_run_benchmarks(self) -> None:
        state = CFDashboardState()
        results = state.run_benchmarks(iterations=10)
        assert len(results) == 6
        assert state.benchmarks is not None


# ---------------------------------------------------------------------------
# Demo state
# ---------------------------------------------------------------------------

class TestDemoState:
    def test_create_demo(self) -> None:
        state = create_demo_state()
        assert state.path_count == 4
        assert state.intrazone_cf == 100

    def test_demo_has_anomaly(self) -> None:
        state = create_demo_state()
        assert len(state.anomalies()) == 1
        assert state.anomalies()[0].path_id == "anomaly-64500"

    def test_demo_best_path(self) -> None:
        state = create_demo_state()
        best = state.best_path()
        assert best is not None

    def test_demo_ranked(self) -> None:
        state = create_demo_state()
        ranked = state.ranked_paths()
        assert len(ranked) == 4
        # Best should be first
        assert ranked[0].accumulated_cf <= ranked[-1].accumulated_cf

    def test_demo_to_dict(self) -> None:
        state = create_demo_state()
        d = state.to_dict()
        assert d["summary"]["paths"] == 4
        assert d["summary"]["anomalies"] == 1
