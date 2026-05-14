# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for Cost Factor (CF) metric per Section 1.6."""

import math

import pytest

from ipv8lab.cost_factor import (
    CFComponents,
    CFPath,
    accumulate_cf,
    cf_total,
    compute_cf,
    great_circle_distance_km,
    is_cf_anomaly,
    physics_floor_ms,
    select_best_path,
)


class TestCFComponents:
    def test_all_zero(self):
        c = CFComponents()
        assert compute_cf(c) == 0

    def test_all_max(self):
        c = CFComponents(
            rtt=1.0, packet_loss=1.0, congestion=1.0,
            stability=1.0, capacity=1.0, economic=1.0, geographic=1.0,
        )
        assert compute_cf(c) == 0xFFFFFFFF

    def test_rtt_only(self):
        c = CFComponents(rtt=0.5)
        cf = compute_cf(c)
        # 0.5 * 0.25 = 0.125 → ~536 million
        assert 0 < cf < 0xFFFFFFFF

    def test_validation_below_zero(self):
        with pytest.raises(ValueError, match="0.0–1.0"):
            CFComponents(rtt=-0.1)

    def test_validation_above_one(self):
        with pytest.raises(ValueError, match="0.0–1.0"):
            CFComponents(packet_loss=1.5)

    def test_custom_weights(self):
        c = CFComponents(rtt=1.0)
        # All weight on RTT
        w = (1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
        assert compute_cf(c, weights=w) == 0xFFFFFFFF

    def test_bad_weight_count(self):
        c = CFComponents()
        with pytest.raises(ValueError, match="7 weights"):
            compute_cf(c, weights=(1.0, 0.0))

    def test_unsupported_version(self):
        c = CFComponents()
        with pytest.raises(ValueError, match="Unsupported"):
            compute_cf(c, version=99)  # type: ignore[arg-type]


class TestAccumulate:
    def test_empty(self):
        assert accumulate_cf([]) == 0

    def test_single_hop(self):
        assert accumulate_cf([1000]) == 1000

    def test_multi_hop(self):
        assert accumulate_cf([100, 200, 300]) == 600

    def test_saturating(self):
        assert accumulate_cf([0xFFFFFFFF, 1]) == 0xFFFFFFFF

    def test_cf_total(self):
        assert cf_total(100, 200) == 300

    def test_cf_total_saturating(self):
        assert cf_total(0xFFFFFFFF, 1) == 0xFFFFFFFF


class TestSelectBestPath:
    def test_selects_lowest(self):
        paths = {"path-a": 500, "path-b": 100, "path-c": 300}
        assert select_best_path(paths) == "path-b"

    def test_empty(self):
        assert select_best_path({}) is None

    def test_single_path(self):
        assert select_best_path({"only": 42}) == "only"


class TestGeographic:
    def test_same_point_zero(self):
        assert great_circle_distance_km(0, 0, 0, 0) == 0.0

    def test_known_distance(self):
        # London (51.5, -0.1) to New York (40.7, -74.0) ≈ 5570 km
        d = great_circle_distance_km(51.5, -0.1, 40.7, -74.0)
        assert 5500 < d < 5700

    def test_antipodal(self):
        d = great_circle_distance_km(0, 0, 0, 180)
        expected = math.pi * 6371.0
        assert abs(d - expected) < 1.0

    def test_physics_floor(self):
        # 1000 km → 5 ms one-way
        assert physics_floor_ms(1000) == pytest.approx(5.0)

    def test_physics_floor_zero(self):
        assert physics_floor_ms(0) == 0.0


class TestCFAnomaly:
    def test_normal_path(self):
        # 1000 km → min RTT = 10 ms, measured 15 ms → OK
        assert not is_cf_anomaly(15.0, 1000.0)

    def test_anomaly_faster_than_light(self):
        # 1000 km → min RTT = 10 ms, measured 5 ms → anomaly!
        assert is_cf_anomaly(5.0, 1000.0)

    def test_exact_physics_limit(self):
        # Exactly at the limit → not anomaly
        assert not is_cf_anomaly(10.0, 1000.0)

    def test_very_close_to_limit(self):
        # Just below → anomaly
        assert is_cf_anomaly(9.99, 1000.0)


class TestCFPath:
    def test_accumulated(self):
        p = CFPath(path_id="a", hops=[100, 200, 300])
        assert p.accumulated_cf == 600

    def test_anomaly_detection(self):
        p = CFPath(path_id="x", hops=[100], distance_km=1000.0, measured_rtt_ms=5.0)
        assert p.anomaly is True

    def test_no_anomaly(self):
        p = CFPath(path_id="y", hops=[100], distance_km=1000.0, measured_rtt_ms=15.0)
        assert p.anomaly is False

    def test_zero_distance_no_anomaly(self):
        p = CFPath(path_id="z", hops=[100], distance_km=0.0, measured_rtt_ms=0.1)
        assert p.anomaly is False

    def test_path_selection_by_cf(self):
        p1 = CFPath(path_id="slow", hops=[500, 500])
        p2 = CFPath(path_id="fast", hops=[100, 100])
        paths = {p1.path_id: p1.accumulated_cf, p2.path_id: p2.accumulated_cf}
        assert select_best_path(paths) == "fast"
