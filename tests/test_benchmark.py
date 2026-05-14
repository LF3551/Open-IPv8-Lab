# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for performance benchmarks."""

from ipv8lab.benchmark import (
    BenchmarkResult,
    bench_address_parse,
    bench_address_to_int,
    bench_checksum,
    bench_packet_deserialize,
    bench_packet_serialize,
    bench_route_lookup,
    run_all,
)


class TestBenchmarkResult:
    def test_ops_per_second(self) -> None:
        r = BenchmarkResult(name="test", iterations=1000, total_seconds=0.5)
        assert r.ops_per_second == 2000.0

    def test_us_per_op(self) -> None:
        r = BenchmarkResult(name="test", iterations=1000, total_seconds=0.001)
        assert r.us_per_op == 1.0

    def test_zero_time(self) -> None:
        r = BenchmarkResult(name="test", iterations=100, total_seconds=0.0)
        assert r.ops_per_second == float("inf")


class TestBenchmarks:
    """Smoke tests — run each benchmark with minimal iterations."""

    def test_address_parse(self) -> None:
        r = bench_address_parse(iterations=10)
        assert r.iterations == 10
        assert r.total_seconds >= 0

    def test_address_to_int(self) -> None:
        r = bench_address_to_int(iterations=10)
        assert r.iterations == 10

    def test_packet_serialize(self) -> None:
        r = bench_packet_serialize(iterations=10)
        assert r.iterations == 10

    def test_packet_deserialize(self) -> None:
        r = bench_packet_deserialize(iterations=10)
        assert r.iterations == 10

    def test_checksum(self) -> None:
        r = bench_checksum(iterations=10)
        assert r.iterations == 10

    def test_route_lookup(self) -> None:
        r = bench_route_lookup(iterations=10)
        assert r.iterations == 10

    def test_run_all(self) -> None:
        results = run_all(iterations=10)
        assert len(results) == 6
        assert all(r.total_seconds >= 0 for r in results)
