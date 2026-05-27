# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""NIC rate limits per draft-thain-ipv8- Section 17.5.

IPv8 certified NIC firmware enforces rate limits that cannot be
overridden by software:

    Broadcasts:            10 per second maximum
    User unauthenticated:  10 per second, max 30 per minute
    User authenticated:    100 per second, max 300 per minute
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum, auto


class TrafficClass(Enum):
    """Traffic classification for rate limiting."""

    BROADCAST = auto()
    UNAUTHENTICATED = auto()
    AUTHENTICATED = auto()


@dataclass
class _Bucket:
    """Token bucket for rate limiting."""

    rate_per_second: int
    rate_per_minute: int
    _second_tokens: int = 0
    _minute_tokens: int = 0
    _last_second: float = 0.0
    _last_minute: float = 0.0

    def allow(self, now: float) -> bool:
        """Check if a packet is allowed and consume a token."""
        current_second = int(now)
        current_minute = int(now / 60)

        if current_second != int(self._last_second):
            self._second_tokens = 0
            self._last_second = now

        if current_minute != int(self._last_minute / 60):
            self._minute_tokens = 0
            self._last_minute = now

        if self._second_tokens >= self.rate_per_second:
            return False
        if self._minute_tokens >= self.rate_per_minute:
            return False

        self._second_tokens += 1
        self._minute_tokens += 1
        return True


# Default rate limits from Section 17.5
_DEFAULT_LIMITS: dict[TrafficClass, tuple[int, int]] = {
    TrafficClass.BROADCAST: (10, 600),        # 10/s, no minute cap (use 600)
    TrafficClass.UNAUTHENTICATED: (10, 30),   # 10/s, 30/min
    TrafficClass.AUTHENTICATED: (100, 300),   # 100/s, 300/min
}


@dataclass
class RateLimiter:
    """NIC firmware rate limiter per Section 17.5."""

    _buckets: dict[TrafficClass, _Bucket] = field(default_factory=dict)
    _clock: object = field(default=None)

    def __post_init__(self) -> None:
        if self._clock is None:
            self._clock = time.monotonic
        for tc, (rps, rpm) in _DEFAULT_LIMITS.items():
            if tc not in self._buckets:
                self._buckets[tc] = _Bucket(rate_per_second=rps, rate_per_minute=rpm)

    def allow(self, traffic_class: TrafficClass, now: float | None = None) -> bool:
        """Check if a packet of the given class is allowed."""
        if now is None:
            now = self._clock()  # type: ignore[operator]
        bucket = self._buckets[traffic_class]
        return bucket.allow(now)

    def remaining(self, traffic_class: TrafficClass) -> tuple[int, int]:
        """Return (remaining_per_second, remaining_per_minute) for a class."""
        b = self._buckets[traffic_class]
        sec_rem = max(0, b.rate_per_second - b._second_tokens)
        min_rem = max(0, b.rate_per_minute - b._minute_tokens)
        return sec_rem, min_rem


def create_rate_limiter(clock: object = None) -> RateLimiter:
    """Create a rate limiter with default Section 17.5 limits."""
    return RateLimiter(_clock=clock)
