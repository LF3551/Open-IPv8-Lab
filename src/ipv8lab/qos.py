# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""QoS — Traffic classification and shaping based on the TOS field.

Implements DiffServ-style traffic classification and multiple queuing
disciplines for IPv8 packets:

* **Traffic Classes** — TOS byte mapped to DSCP-like classes (EF, AF, BE, CS).
* **Priority Queuing (PQ)** — strict priority: highest class always first.
* **Weighted Fair Queuing (WFQ)** — configurable weights per class.
* **Token Bucket Shaper** — rate limiting with burst tolerance.
* **Traffic Policer** — drop or remark packets exceeding rate.

Usage::

    shaper = TrafficShaper(policy=QoSPolicy.WFQ)
    shaper.configure_class(TrafficClass.EF, rate_bps=1_000_000, weight=50)
    shaper.configure_class(TrafficClass.AF, rate_bps=500_000, weight=30)
    shaper.enqueue(packet)
    next_pkt = shaper.dequeue()
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass
from enum import IntEnum

from ipv8lab.packet import IPv8Packet


# ---------------------------------------------------------------------------
# Traffic classes
# ---------------------------------------------------------------------------


class TrafficClass(IntEnum):
    """DiffServ-style traffic classes derived from TOS field."""

    # DSCP-like: TOS bits 7-2 encode the class
    EF = 46  # Expedited Forwarding (voice, real-time)
    AF41 = 34  # Assured Forwarding class 4
    AF31 = 26  # Assured Forwarding class 3
    AF21 = 18  # Assured Forwarding class 2
    AF11 = 10  # Assured Forwarding class 1
    CS6 = 48  # Control/signalling
    CS7 = 56  # Network control
    BE = 0  # Best Effort (default)


class QoSPolicy(IntEnum):
    """Available queuing disciplines."""

    PRIORITY = 0  # Strict priority queuing
    WFQ = 1  # Weighted fair queuing
    FIFO = 2  # First-in first-out (no QoS)


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

# Default TOS → TrafficClass mapping
_TOS_CLASS_MAP: dict[int, TrafficClass] = {}


def _init_tos_map() -> None:
    """Build default TOS → class mapping."""
    for tc in TrafficClass:
        dscp = int(tc)
        tos_val = dscp << 2  # DSCP occupies bits 7-2
        _TOS_CLASS_MAP[tos_val] = tc


_init_tos_map()


def classify(packet: IPv8Packet) -> TrafficClass:
    """Classify a packet based on its TOS field.

    Extracts DSCP from TOS bits 7-2 and maps to TrafficClass.
    Falls back to BE (Best Effort) for unknown values.
    """
    dscp = (packet.tos >> 2) & 0x3F
    try:
        return TrafficClass(dscp)
    except ValueError:
        return TrafficClass.BE


def remark(packet: IPv8Packet, new_class: TrafficClass) -> IPv8Packet:
    """Create a copy of the packet with TOS remarked to a new class."""
    new_tos = (int(new_class) << 2) | (packet.tos & 0x03)  # preserve ECN bits
    return IPv8Packet(
        src=packet.src,
        dst=packet.dst,
        payload=packet.payload,
        version=packet.version,
        ihl=packet.ihl,
        tos=new_tos,
        identification=packet.identification,
        flags=packet.flags,
        fragment_offset=packet.fragment_offset,
        ttl=packet.ttl,
        protocol=packet.protocol,
    )


# ---------------------------------------------------------------------------
# Token Bucket
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class TokenBucket:
    """Token bucket for rate limiting.

    Parameters
    ----------
    rate_bps
        Sustained rate in bits per second.
    burst_bytes
        Maximum burst size in bytes.
    """

    rate_bps: int
    burst_bytes: int
    _tokens: float = 0.0
    _last_refill: float = -1.0

    def __post_init__(self) -> None:
        self._tokens = float(self.burst_bytes)
        self._last_refill = -1.0

    def refill(self, now: float) -> None:
        """Add tokens based on elapsed time."""
        if self._last_refill < 0.0:
            self._last_refill = now
            return
            return
        elapsed = now - self._last_refill
        if elapsed <= 0:
            return
        added = elapsed * (self.rate_bps / 8.0)  # bytes per second
        self._tokens = min(self._tokens + added, float(self.burst_bytes))
        self._last_refill = now

    def consume(self, size: int, now: float) -> bool:
        """Try to consume tokens for a packet. Returns True if allowed."""
        self.refill(now)
        if self._tokens >= size:
            self._tokens -= size
            return True
        return False

    @property
    def available_tokens(self) -> float:
        return self._tokens


# ---------------------------------------------------------------------------
# Queue class config
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ClassConfig:
    """Configuration for a single traffic class queue."""

    traffic_class: TrafficClass
    rate_bps: int = 0  # 0 = unlimited
    burst_bytes: int = 0
    weight: int = 1  # for WFQ
    max_queue: int = 1000  # max packets in queue
    bucket: TokenBucket | None = None
    drop_count: int = 0
    enqueue_count: int = 0
    dequeue_count: int = 0

    def to_dict(self) -> dict[str, object]:
        return {
            "traffic_class": self.traffic_class.name,
            "rate_bps": self.rate_bps,
            "burst_bytes": self.burst_bytes,
            "weight": self.weight,
            "max_queue": self.max_queue,
            "drop_count": self.drop_count,
            "enqueue_count": self.enqueue_count,
            "dequeue_count": self.dequeue_count,
        }


# ---------------------------------------------------------------------------
# Shaper stats
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ShaperStats:
    """Aggregate shaper statistics."""

    total_enqueued: int = 0
    total_dequeued: int = 0
    total_dropped: int = 0
    total_shaped: int = 0
    queue_depth: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "total_enqueued": self.total_enqueued,
            "total_dequeued": self.total_dequeued,
            "total_dropped": self.total_dropped,
            "total_shaped": self.total_shaped,
            "queue_depth": self.queue_depth,
        }


# ---------------------------------------------------------------------------
# Traffic Shaper
# ---------------------------------------------------------------------------


class TrafficShaper:
    """QoS traffic shaper with multiple queuing disciplines.

    Supports priority queuing, weighted fair queuing, and simple FIFO.
    Each traffic class can have its own rate limit via token bucket.
    """

    def __init__(
        self,
        policy: QoSPolicy = QoSPolicy.PRIORITY,
        *,
        clock: object | None = None,
    ) -> None:
        self._policy = policy
        self._clock = clock if clock is not None else time.monotonic
        self._queues: dict[TrafficClass, deque[IPv8Packet]] = {}
        self._configs: dict[TrafficClass, ClassConfig] = {}
        self._stats = ShaperStats()
        self._wfq_counters: dict[TrafficClass, int] = {}

        # Initialize default queues for all classes
        for tc in TrafficClass:
            self._queues[tc] = deque()
            self._configs[tc] = ClassConfig(traffic_class=tc)
            self._wfq_counters[tc] = 0

    # ---- properties ----

    @property
    def policy(self) -> QoSPolicy:
        return self._policy

    @property
    def queue_depth(self) -> int:
        return sum(len(q) for q in self._queues.values())

    # ---- configuration ----

    def configure_class(
        self,
        tc: TrafficClass,
        *,
        rate_bps: int = 0,
        burst_bytes: int = 0,
        weight: int = 1,
        max_queue: int = 1000,
    ) -> None:
        """Configure a traffic class queue."""
        bucket = None
        if rate_bps > 0:
            if burst_bytes <= 0:
                burst_bytes = rate_bps // 8  # 1 second of burst
            bucket = TokenBucket(rate_bps=rate_bps, burst_bytes=burst_bytes)
        self._configs[tc] = ClassConfig(
            traffic_class=tc,
            rate_bps=rate_bps,
            burst_bytes=burst_bytes,
            weight=max(1, weight),
            max_queue=max_queue,
            bucket=bucket,
        )

    # ---- enqueue ----

    def enqueue(self, packet: IPv8Packet) -> bool:
        """Classify and enqueue a packet.

        Returns True if accepted, False if dropped (queue full or policed).
        """
        tc = classify(packet)
        cfg = self._configs[tc]
        q = self._queues[tc]

        # Check queue limit
        if len(q) >= cfg.max_queue:
            cfg.drop_count += 1
            self._stats.total_dropped += 1
            return False

        # Check token bucket (policer)
        if cfg.bucket is not None:
            now: float = self._clock()  # type: ignore[operator]
            pkt_size = len(packet.payload) + 28
            if not cfg.bucket.consume(pkt_size, now):
                cfg.drop_count += 1
                self._stats.total_dropped += 1
                self._stats.total_shaped += 1
                return False

        q.append(packet)
        cfg.enqueue_count += 1
        self._stats.total_enqueued += 1
        return True

    # ---- dequeue ----

    def dequeue(self) -> IPv8Packet | None:
        """Dequeue the next packet according to the configured policy."""
        if self._policy == QoSPolicy.PRIORITY:
            return self._dequeue_priority()
        elif self._policy == QoSPolicy.WFQ:
            return self._dequeue_wfq()
        else:
            return self._dequeue_fifo()

    def _dequeue_priority(self) -> IPv8Packet | None:
        """Strict priority: highest class value first."""
        # Higher IntEnum value = higher priority
        for tc in sorted(TrafficClass, reverse=True):
            q = self._queues[tc]
            if q:
                pkt = q.popleft()
                self._configs[tc].dequeue_count += 1
                self._stats.total_dequeued += 1
                return pkt
        return None

    def _dequeue_wfq(self) -> IPv8Packet | None:
        """Weighted fair queuing: round-robin weighted by class weight."""
        # Find non-empty queues
        active = [(tc, self._configs[tc].weight) for tc in TrafficClass
                  if self._queues[tc]]
        if not active:
            return None

        # Pick the class with lowest (counter / weight) ratio
        best_tc: TrafficClass | None = None
        best_ratio = float("inf")
        for tc, w in active:
            ratio = self._wfq_counters[tc] / w
            if ratio < best_ratio:
                best_ratio = ratio
                best_tc = tc

        if best_tc is None:
            return None

        q = self._queues[best_tc]
        pkt = q.popleft()
        self._wfq_counters[best_tc] += 1
        self._configs[best_tc].dequeue_count += 1
        self._stats.total_dequeued += 1
        return pkt

    def _dequeue_fifo(self) -> IPv8Packet | None:
        """Simple FIFO across all queues (no priority)."""
        for tc in TrafficClass:
            q = self._queues[tc]
            if q:
                pkt = q.popleft()
                self._configs[tc].dequeue_count += 1
                self._stats.total_dequeued += 1
                return pkt
        return None

    # ---- queries ----

    def class_stats(self, tc: TrafficClass) -> ClassConfig:
        return self._configs[tc]

    def all_class_stats(self) -> list[ClassConfig]:
        return [self._configs[tc] for tc in TrafficClass]

    def stats(self) -> ShaperStats:
        self._stats.queue_depth = self.queue_depth
        return self._stats

    def get_queue_lengths(self) -> dict[str, int]:
        """Return queue length per traffic class."""
        return {tc.name: len(self._queues[tc]) for tc in TrafficClass}

    def to_dict(self) -> dict[str, object]:
        return {
            "policy": self._policy.name,
            "stats": self.stats().to_dict(),
            "classes": [cfg.to_dict() for cfg in self.all_class_stats()],
            "queue_lengths": self.get_queue_lengths(),
        }

    def clear(self) -> None:
        """Reset all queues and stats."""
        for tc in TrafficClass:
            self._queues[tc].clear()
            self._configs[tc] = ClassConfig(traffic_class=tc)
            self._wfq_counters[tc] = 0
        self._stats = ShaperStats()
