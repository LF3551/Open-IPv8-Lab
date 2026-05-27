# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Performance benchmarks for IPv8 Lab core operations."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable

from ipv8lab.address import IPv8Address
from ipv8lab.checksum import crc32_checksum
from ipv8lab.packet import IPv8Packet
from ipv8lab.route import Route, RouteTable


@dataclass(slots=True)
class BenchmarkResult:
    """Result of a single benchmark run."""

    name: str
    iterations: int
    total_seconds: float

    @property
    def ops_per_second(self) -> float:
        if self.total_seconds == 0:
            return float("inf")
        return self.iterations / self.total_seconds

    @property
    def us_per_op(self) -> float:
        if self.iterations == 0:
            return 0.0
        return (self.total_seconds * 1_000_000) / self.iterations


def _bench(name: str, func: Callable[[], object], iterations: int = 10_000) -> BenchmarkResult:
    """Run a function N times and measure elapsed time."""
    start = time.perf_counter()
    for _ in range(iterations):
        func()
    elapsed = time.perf_counter() - start
    return BenchmarkResult(name=name, iterations=iterations, total_seconds=elapsed)


def bench_address_parse(iterations: int = 10_000) -> BenchmarkResult:
    """Benchmark IPv8Address.parse()."""
    return _bench(
        "address_parse",
        lambda: IPv8Address.parse("64496-192.0.2.1"),
        iterations,
    )


def bench_address_to_int(iterations: int = 10_000) -> BenchmarkResult:
    """Benchmark IPv8Address.to_int()."""
    addr = IPv8Address.parse("64496-192.0.2.1")
    return _bench("address_to_int", addr.to_int, iterations)


def bench_packet_serialize(iterations: int = 10_000) -> BenchmarkResult:
    """Benchmark IPv8Packet serialization."""
    src = IPv8Address.parse("64496-192.0.2.1")
    dst = IPv8Address.parse("64497-198.51.100.7")
    pkt = IPv8Packet(src=src, dst=dst, payload=b"benchmark-payload")
    return _bench("packet_serialize", pkt.to_bytes, iterations)


def bench_packet_deserialize(iterations: int = 10_000) -> BenchmarkResult:
    """Benchmark IPv8Packet deserialization."""
    src = IPv8Address.parse("64496-192.0.2.1")
    dst = IPv8Address.parse("64497-198.51.100.7")
    pkt = IPv8Packet(src=src, dst=dst, payload=b"benchmark-payload")
    raw = pkt.to_bytes()
    return _bench("packet_deserialize", lambda: IPv8Packet.from_bytes(raw), iterations)


def bench_checksum(iterations: int = 10_000) -> BenchmarkResult:
    """Benchmark CRC32 checksum on a 64-byte block."""
    data = b"x" * 64
    return _bench("crc32_checksum", lambda: crc32_checksum(data), iterations)


def bench_route_lookup(iterations: int = 10_000) -> BenchmarkResult:
    """Benchmark route table lookup with 100 routes."""
    table = RouteTable()
    for i in range(100):
        table.add_route(
            Route(
                destination_prefix=f"{i}.0.0.0",
                next_hop=f"router-{i}",
                interface=f"eth{i}",
            )
        )
    dst = IPv8Address.parse("50.0.0.0.10.0.0.1")
    return _bench("route_lookup", lambda: table.find_route(dst), iterations)


def run_all(iterations: int = 10_000) -> list[BenchmarkResult]:
    """Run all benchmarks and return results."""
    return [
        bench_address_parse(iterations),
        bench_address_to_int(iterations),
        bench_packet_serialize(iterations),
        bench_packet_deserialize(iterations),
        bench_checksum(iterations),
        bench_route_lookup(iterations),
    ]
