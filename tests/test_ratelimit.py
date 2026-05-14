# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for NIC rate limits per Section 17.5."""

from ipv8lab.ratelimit import (
    RateLimiter,
    TrafficClass,
    create_rate_limiter,
)


class TestBroadcastLimits:
    def test_allows_10_per_second(self):
        rl = create_rate_limiter()
        t = 1000.0
        for _ in range(10):
            assert rl.allow(TrafficClass.BROADCAST, now=t)
        assert not rl.allow(TrafficClass.BROADCAST, now=t)

    def test_resets_next_second(self):
        rl = create_rate_limiter()
        for _ in range(10):
            rl.allow(TrafficClass.BROADCAST, now=100.0)
        assert not rl.allow(TrafficClass.BROADCAST, now=100.5)
        assert rl.allow(TrafficClass.BROADCAST, now=101.0)


class TestUnauthenticatedLimits:
    def test_allows_10_per_second(self):
        rl = create_rate_limiter()
        t = 1000.0
        for _ in range(10):
            assert rl.allow(TrafficClass.UNAUTHENTICATED, now=t)
        assert not rl.allow(TrafficClass.UNAUTHENTICATED, now=t)

    def test_minute_cap_30(self):
        rl = create_rate_limiter()
        base = 60.0  # start of a minute
        count = 0
        for sec in range(10):
            for _ in range(10):
                if rl.allow(TrafficClass.UNAUTHENTICATED, now=base + sec):
                    count += 1
        assert count == 30  # 10/s but capped at 30/min

    def test_minute_resets(self):
        rl = create_rate_limiter()
        base = 60.0
        for sec in range(10):
            for _ in range(10):
                rl.allow(TrafficClass.UNAUTHENTICATED, now=base + sec)
        # New minute
        assert rl.allow(TrafficClass.UNAUTHENTICATED, now=120.0)


class TestAuthenticatedLimits:
    def test_allows_100_per_second(self):
        rl = create_rate_limiter()
        t = 1000.0
        for _ in range(100):
            assert rl.allow(TrafficClass.AUTHENTICATED, now=t)
        assert not rl.allow(TrafficClass.AUTHENTICATED, now=t)

    def test_minute_cap_300(self):
        rl = create_rate_limiter()
        base = 60.0
        count = 0
        for sec in range(10):
            for _ in range(100):
                if rl.allow(TrafficClass.AUTHENTICATED, now=base + sec):
                    count += 1
        assert count == 300  # 100/s but capped at 300/min


class TestRemaining:
    def test_initial_remaining(self):
        rl = create_rate_limiter()
        s, m = rl.remaining(TrafficClass.BROADCAST)
        assert s == 10
        assert m == 600

    def test_after_one_packet(self):
        rl = create_rate_limiter()
        rl.allow(TrafficClass.UNAUTHENTICATED, now=100.0)
        s, m = rl.remaining(TrafficClass.UNAUTHENTICATED)
        assert s == 9
        assert m == 29


class TestFactory:
    def test_create_rate_limiter(self):
        rl = create_rate_limiter()
        assert isinstance(rl, RateLimiter)

    def test_independent_classes(self):
        rl = create_rate_limiter()
        for _ in range(10):
            rl.allow(TrafficClass.BROADCAST, now=100.0)
        assert not rl.allow(TrafficClass.BROADCAST, now=100.0)
        assert rl.allow(TrafficClass.AUTHENTICATED, now=100.0)
