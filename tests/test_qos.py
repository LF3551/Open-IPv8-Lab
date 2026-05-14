# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for QoS traffic shaping module."""

from __future__ import annotations

from ipv8lab.address import IPv8Address
from ipv8lab.packet import IPv8Packet
from ipv8lab.qos import (
    ClassConfig,
    QoSPolicy,
    ShaperStats,
    TokenBucket,
    TrafficClass,
    TrafficShaper,
    classify,
    remark,
)


def _pkt(tos: int = 0, src: str = "64496.10.0.1.10", dst: str = "64497.10.0.1.1") -> IPv8Packet:
    return IPv8Packet(
        src=IPv8Address.parse(src),
        dst=IPv8Address.parse(dst),
        tos=tos,
        payload=b"qos-test",
    )


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


class TestClassify:
    def test_be_default(self) -> None:
        assert classify(_pkt(tos=0)) == TrafficClass.BE

    def test_ef(self) -> None:
        # EF = DSCP 46, TOS = 46 << 2 = 184
        assert classify(_pkt(tos=184)) == TrafficClass.EF

    def test_af41(self) -> None:
        # AF41 = DSCP 34, TOS = 34 << 2 = 136
        assert classify(_pkt(tos=136)) == TrafficClass.AF41

    def test_af31(self) -> None:
        # AF31 = DSCP 26, TOS = 26 << 2 = 104
        assert classify(_pkt(tos=104)) == TrafficClass.AF31

    def test_af21(self) -> None:
        # AF21 = DSCP 18, TOS = 18 << 2 = 72
        assert classify(_pkt(tos=72)) == TrafficClass.AF21

    def test_af11(self) -> None:
        # AF11 = DSCP 10, TOS = 10 << 2 = 40
        assert classify(_pkt(tos=40)) == TrafficClass.AF11

    def test_cs6(self) -> None:
        # CS6 = DSCP 48, TOS = 48 << 2 = 192
        assert classify(_pkt(tos=192)) == TrafficClass.CS6

    def test_cs7(self) -> None:
        # CS7 = DSCP 56, TOS = 56 << 2 = 224
        assert classify(_pkt(tos=224)) == TrafficClass.CS7

    def test_unknown_dscp_falls_to_be(self) -> None:
        # DSCP 1 is not defined → BE
        assert classify(_pkt(tos=4)) == TrafficClass.BE

    def test_ecn_bits_ignored(self) -> None:
        # TOS = 184 | 0x03 (ECN bits set)
        assert classify(_pkt(tos=187)) == TrafficClass.EF


# ---------------------------------------------------------------------------
# Remark
# ---------------------------------------------------------------------------


class TestRemark:
    def test_remark_to_ef(self) -> None:
        pkt = _pkt(tos=0)
        remarked = remark(pkt, TrafficClass.EF)
        assert classify(remarked) == TrafficClass.EF
        assert remarked.tos == 184

    def test_remark_preserves_ecn(self) -> None:
        pkt = _pkt(tos=3)  # ECN bits set
        remarked = remark(pkt, TrafficClass.AF41)
        assert (remarked.tos & 0x03) == 3  # ECN preserved
        assert classify(remarked) == TrafficClass.AF41

    def test_remark_preserves_payload(self) -> None:
        pkt = _pkt(tos=0)
        remarked = remark(pkt, TrafficClass.EF)
        assert remarked.payload == pkt.payload
        assert remarked.src == pkt.src
        assert remarked.dst == pkt.dst


# ---------------------------------------------------------------------------
# Token Bucket
# ---------------------------------------------------------------------------


class TestTokenBucket:
    def test_initial_tokens(self) -> None:
        tb = TokenBucket(rate_bps=8000, burst_bytes=1000)
        assert tb.available_tokens == 1000.0

    def test_consume_within_burst(self) -> None:
        tb = TokenBucket(rate_bps=8000, burst_bytes=1000)
        assert tb.consume(500, 0.0) is True
        assert tb.available_tokens == 500.0

    def test_consume_exceeds_tokens(self) -> None:
        tb = TokenBucket(rate_bps=8000, burst_bytes=100)
        assert tb.consume(50, 0.0) is True
        assert tb.consume(60, 0.0) is False  # only 50 left

    def test_refill(self) -> None:
        tb = TokenBucket(rate_bps=8000, burst_bytes=1000)
        tb.consume(1000, 0.0)  # drain all
        assert tb.available_tokens == 0.0
        # After 1 second at 8000bps = 1000 bytes/sec
        tb.refill(1.0)
        assert tb.available_tokens == 1000.0

    def test_refill_capped_at_burst(self) -> None:
        tb = TokenBucket(rate_bps=80000, burst_bytes=1000)
        tb.consume(500, 0.0)
        # Even after long time, capped at burst
        tb.refill(100.0)
        assert tb.available_tokens == 1000.0


# ---------------------------------------------------------------------------
# TrafficShaper — Priority Queuing
# ---------------------------------------------------------------------------


class TestPriorityQueuing:
    def test_higher_class_first(self) -> None:
        shaper = TrafficShaper(policy=QoSPolicy.PRIORITY)
        shaper.enqueue(_pkt(tos=0))    # BE
        shaper.enqueue(_pkt(tos=184))  # EF
        shaper.enqueue(_pkt(tos=104))  # AF31
        # EF > AF31 > BE
        p1 = shaper.dequeue()
        p2 = shaper.dequeue()
        p3 = shaper.dequeue()
        assert p1 is not None and classify(p1) == TrafficClass.EF
        assert p2 is not None and classify(p2) == TrafficClass.AF31
        assert p3 is not None and classify(p3) == TrafficClass.BE

    def test_same_class_fifo(self) -> None:
        shaper = TrafficShaper(policy=QoSPolicy.PRIORITY)
        pkt1 = IPv8Packet(src=IPv8Address.parse("64496.10.0.1.10"),
                          dst=IPv8Address.parse("64497.10.0.1.1"), tos=0, payload=b"first")
        pkt2 = IPv8Packet(src=IPv8Address.parse("64496.10.0.1.10"),
                          dst=IPv8Address.parse("64497.10.0.1.1"), tos=0, payload=b"second")
        shaper.enqueue(pkt1)
        shaper.enqueue(pkt2)
        assert shaper.dequeue() is pkt1
        assert shaper.dequeue() is pkt2

    def test_dequeue_empty(self) -> None:
        shaper = TrafficShaper(policy=QoSPolicy.PRIORITY)
        assert shaper.dequeue() is None

    def test_queue_depth(self) -> None:
        shaper = TrafficShaper(policy=QoSPolicy.PRIORITY)
        shaper.enqueue(_pkt())
        shaper.enqueue(_pkt())
        assert shaper.queue_depth == 2
        shaper.dequeue()
        assert shaper.queue_depth == 1


# ---------------------------------------------------------------------------
# TrafficShaper — WFQ
# ---------------------------------------------------------------------------


class TestWFQ:
    def test_weighted_distribution(self) -> None:
        shaper = TrafficShaper(policy=QoSPolicy.WFQ)
        shaper.configure_class(TrafficClass.EF, weight=3)
        shaper.configure_class(TrafficClass.BE, weight=1)
        # Enqueue 4 EF and 4 BE
        for _ in range(4):
            shaper.enqueue(_pkt(tos=184))
        for _ in range(4):
            shaper.enqueue(_pkt(tos=0))
        # Dequeue all 8 — expect ~3:1 ratio pattern
        classes: list[str] = []
        while True:
            p = shaper.dequeue()
            if p is None:
                break
            classes.append(classify(p).name)
        # First 4 should favor EF heavily
        ef_in_first_4 = classes[:4].count("EF")
        assert ef_in_first_4 >= 3  # at least 3 of first 4 are EF

    def test_empty_returns_none(self) -> None:
        shaper = TrafficShaper(policy=QoSPolicy.WFQ)
        assert shaper.dequeue() is None


# ---------------------------------------------------------------------------
# TrafficShaper — FIFO
# ---------------------------------------------------------------------------


class TestFIFO:
    def test_fifo_order(self) -> None:
        shaper = TrafficShaper(policy=QoSPolicy.FIFO)
        pkt_be = _pkt(tos=0)
        # In FIFO, enqueue order iterates through TrafficClass enum
        # Since EF and BE go to different internal queues, test single class
        shaper.enqueue(pkt_be)
        shaper.enqueue(pkt_be)
        p1 = shaper.dequeue()
        assert p1 is pkt_be


# ---------------------------------------------------------------------------
# Rate limiting / policer
# ---------------------------------------------------------------------------


class TestRateLimiting:
    def test_drop_when_rate_exceeded(self) -> None:
        t = 0.0

        def clock() -> float:
            return t

        shaper = TrafficShaper(policy=QoSPolicy.FIFO, clock=clock)
        # 800 bps = 100 bytes/sec, burst = 100 bytes
        shaper.configure_class(TrafficClass.BE, rate_bps=800, burst_bytes=100)
        # First packet (37 bytes) should pass
        assert shaper.enqueue(_pkt()) is True
        # Second (37 bytes, total 74) should pass
        assert shaper.enqueue(_pkt()) is True
        # Third (37 bytes, total 111 > 100) should be dropped
        assert shaper.enqueue(_pkt()) is False

    def test_rate_refills(self) -> None:
        t = 0.0

        def clock() -> float:
            return t

        shaper = TrafficShaper(policy=QoSPolicy.FIFO, clock=clock)
        shaper.configure_class(TrafficClass.BE, rate_bps=8000, burst_bytes=100)
        # Fill up
        shaper.enqueue(_pkt())  # 37 bytes
        shaper.enqueue(_pkt())  # 37 bytes, 74 total consumed
        assert shaper.enqueue(_pkt()) is False  # 111 > 100

        t = 1.0  # 1 second later: refill 1000 bytes
        assert shaper.enqueue(_pkt()) is True

    def test_max_queue_drop(self) -> None:
        shaper = TrafficShaper(policy=QoSPolicy.FIFO)
        shaper.configure_class(TrafficClass.BE, max_queue=3)
        for _ in range(3):
            assert shaper.enqueue(_pkt()) is True
        assert shaper.enqueue(_pkt()) is False  # queue full

    def test_stats_shaped(self) -> None:
        t = 0.0

        def clock() -> float:
            return t

        shaper = TrafficShaper(policy=QoSPolicy.FIFO, clock=clock)
        shaper.configure_class(TrafficClass.BE, rate_bps=800, burst_bytes=50)
        shaper.enqueue(_pkt())  # 37 bytes OK
        shaper.enqueue(_pkt())  # 37 bytes > 50-37=13 → shaped drop
        s = shaper.stats()
        assert s.total_shaped == 1
        assert s.total_dropped == 1


# ---------------------------------------------------------------------------
# Stats & serialization
# ---------------------------------------------------------------------------


class TestStatsAndSerialization:
    def test_stats(self) -> None:
        shaper = TrafficShaper(policy=QoSPolicy.PRIORITY)
        shaper.enqueue(_pkt())
        shaper.dequeue()
        s = shaper.stats()
        assert isinstance(s, ShaperStats)
        assert s.total_enqueued == 1
        assert s.total_dequeued == 1

    def test_to_dict(self) -> None:
        shaper = TrafficShaper(policy=QoSPolicy.PRIORITY)
        shaper.enqueue(_pkt())
        d = shaper.to_dict()
        assert d["policy"] == "PRIORITY"
        assert "stats" in d
        assert "classes" in d

    def test_get_queue_lengths(self) -> None:
        shaper = TrafficShaper(policy=QoSPolicy.PRIORITY)
        shaper.enqueue(_pkt(tos=0))
        shaper.enqueue(_pkt(tos=184))
        lengths = shaper.get_queue_lengths()
        assert lengths["BE"] == 1
        assert lengths["EF"] == 1

    def test_class_stats(self) -> None:
        shaper = TrafficShaper(policy=QoSPolicy.PRIORITY)
        shaper.enqueue(_pkt())
        cfg = shaper.class_stats(TrafficClass.BE)
        assert isinstance(cfg, ClassConfig)
        assert cfg.enqueue_count == 1

    def test_clear(self) -> None:
        shaper = TrafficShaper(policy=QoSPolicy.PRIORITY)
        shaper.enqueue(_pkt())
        shaper.clear()
        assert shaper.queue_depth == 0
        assert shaper.stats().total_enqueued == 0
