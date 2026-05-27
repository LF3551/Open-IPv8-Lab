# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for NetFlow8 flow monitoring module."""

from __future__ import annotations

import os
import tempfile

from ipv8lab.address import IPv8Address
from ipv8lab.netflow8 import (
    BINARY_RECORD_SIZE,
    CollectorStats,
    FlowCollector,
    FlowKey,
    FlowRecord,
    decode_record,
    encode_record,
    read_nf8,
    write_nf8,
)
from ipv8lab.packet import IPv8Packet


def _pkt(
    src: str = "64496-10.0.1.10",
    dst: str = "64497-10.0.1.1",
    proto: int = 253,
    tos: int = 0,
    ttl: int = 64,
) -> IPv8Packet:
    return IPv8Packet(
        src=IPv8Address.parse(src),
        dst=IPv8Address.parse(dst),
        protocol=proto,
        tos=tos,
        ttl=ttl,
        payload=b"test-flow",
    )


# ---------------------------------------------------------------------------
# FlowKey
# ---------------------------------------------------------------------------


class TestFlowKey:
    def test_create(self) -> None:
        k = FlowKey(
            src_addr=IPv8Address.parse("64496-10.0.1.10"),
            dst_addr=IPv8Address.parse("64497-10.0.1.1"),
            protocol=6,
            src_port=12345,
            dst_port=80,
        )
        assert k.protocol == 6
        assert k.src_port == 12345

    def test_to_dict(self) -> None:
        k = FlowKey(
            src_addr=IPv8Address.parse("64496-10.0.1.10"),
            dst_addr=IPv8Address.parse("64497-10.0.1.1"),
            protocol=6,
        )
        d = k.to_dict()
        assert d["protocol"] == 6
        assert "src_addr" in d

    def test_reverse(self) -> None:
        k = FlowKey(
            src_addr=IPv8Address.parse("64496-10.0.1.10"),
            dst_addr=IPv8Address.parse("64497-10.0.1.1"),
            protocol=6,
            src_port=12345,
            dst_port=80,
        )
        r = k.reverse()
        assert str(r.src_addr) == str(k.dst_addr)
        assert str(r.dst_addr) == str(k.src_addr)
        assert r.src_port == k.dst_port
        assert r.dst_port == k.src_port

    def test_frozen(self) -> None:
        k = FlowKey(
            src_addr=IPv8Address.parse("64496-10.0.1.10"),
            dst_addr=IPv8Address.parse("64497-10.0.1.1"),
            protocol=6,
        )
        # Should be hashable (frozen)
        assert hash(k) is not None

    def test_equality(self) -> None:
        k1 = FlowKey(
            src_addr=IPv8Address.parse("64496-10.0.1.10"),
            dst_addr=IPv8Address.parse("64497-10.0.1.1"),
            protocol=6,
            src_port=80,
            dst_port=443,
        )
        k2 = FlowKey(
            src_addr=IPv8Address.parse("64496-10.0.1.10"),
            dst_addr=IPv8Address.parse("64497-10.0.1.1"),
            protocol=6,
            src_port=80,
            dst_port=443,
        )
        assert k1 == k2


# ---------------------------------------------------------------------------
# FlowRecord
# ---------------------------------------------------------------------------


class TestFlowRecord:
    def test_duration(self) -> None:
        key = FlowKey(
            src_addr=IPv8Address.parse("64496-10.0.1.10"),
            dst_addr=IPv8Address.parse("64497-10.0.1.1"),
            protocol=6,
        )
        rec = FlowRecord(key=key, first_ts=100.0, last_ts=110.5)
        assert rec.duration == 10.5

    def test_duration_zero(self) -> None:
        key = FlowKey(
            src_addr=IPv8Address.parse("64496-10.0.1.10"),
            dst_addr=IPv8Address.parse("64497-10.0.1.1"),
            protocol=6,
        )
        rec = FlowRecord(key=key, first_ts=100.0, last_ts=100.0)
        assert rec.duration == 0.0

    def test_to_dict(self) -> None:
        key = FlowKey(
            src_addr=IPv8Address.parse("64496-10.0.1.10"),
            dst_addr=IPv8Address.parse("64497-10.0.1.1"),
            protocol=6,
        )
        rec = FlowRecord(key=key, packets=42, octets=1234, first_ts=1.0, last_ts=2.0)
        d = rec.to_dict()
        assert d["packets"] == 42
        assert d["octets"] == 1234
        assert d["duration"] == 1.0


# ---------------------------------------------------------------------------
# Binary encoding
# ---------------------------------------------------------------------------


class TestBinaryEncoding:
    def test_roundtrip(self) -> None:
        key = FlowKey(
            src_addr=IPv8Address.parse("64496-10.0.1.10"),
            dst_addr=IPv8Address.parse("64497-10.0.1.1"),
            protocol=6,
            src_port=12345,
            dst_port=80,
        )
        rec = FlowRecord(
            key=key, packets=100, octets=5000,
            first_ts=1000.0, last_ts=1060.0,
            tos=4, min_ttl=60, max_ttl=64,
        )
        data = encode_record(rec)
        assert len(data) == BINARY_RECORD_SIZE
        decoded = decode_record(data)
        assert decoded.packets == rec.packets
        assert decoded.octets == rec.octets
        assert decoded.tos == rec.tos
        assert decoded.min_ttl == rec.min_ttl
        assert decoded.max_ttl == rec.max_ttl
        assert str(decoded.key.src_addr) == str(rec.key.src_addr)
        assert str(decoded.key.dst_addr) == str(rec.key.dst_addr)
        assert decoded.key.src_port == rec.key.src_port
        assert decoded.key.dst_port == rec.key.dst_port

    def test_encode_size(self) -> None:
        key = FlowKey(
            src_addr=IPv8Address.parse("64496-10.0.1.10"),
            dst_addr=IPv8Address.parse("64497-10.0.1.1"),
            protocol=253,
        )
        rec = FlowRecord(key=key)
        assert len(encode_record(rec)) == BINARY_RECORD_SIZE


# ---------------------------------------------------------------------------
# NF8 file I/O
# ---------------------------------------------------------------------------


class TestNF8File:
    def test_write_read_roundtrip(self) -> None:
        key = FlowKey(
            src_addr=IPv8Address.parse("64496-10.0.1.10"),
            dst_addr=IPv8Address.parse("64497-10.0.1.1"),
            protocol=6,
            src_port=80,
            dst_port=443,
        )
        records = [
            FlowRecord(key=key, packets=10, octets=500, first_ts=1.0, last_ts=2.0),
            FlowRecord(key=key.reverse(), packets=5, octets=250, first_ts=1.1, last_ts=1.9),
        ]
        with tempfile.NamedTemporaryFile(suffix=".nf8", delete=False) as f:
            path = f.name
        try:
            n = write_nf8(records, path)
            assert n == 2
            loaded = read_nf8(path)
            assert len(loaded) == 2
            assert loaded[0].packets == 10
            assert loaded[1].packets == 5
        finally:
            os.unlink(path)

    def test_empty_file(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".nf8", delete=False) as f:
            path = f.name
        try:
            write_nf8([], path)
            loaded = read_nf8(path)
            assert len(loaded) == 0
        finally:
            os.unlink(path)

    def test_bad_magic(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".nf8", delete=False) as f:
            f.write(b"\x00\x00\x00\x00\x00\x00\x00\x00")
            path = f.name
        try:
            try:
                read_nf8(path)
                assert False, "Should have raised ValueError"
            except ValueError as e:
                assert "magic" in str(e).lower()
        finally:
            os.unlink(path)

    def test_truncated_header(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".nf8", delete=False) as f:
            f.write(b"\x4E\x46")
            path = f.name
        try:
            try:
                read_nf8(path)
                assert False, "Should have raised ValueError"
            except ValueError as e:
                assert "truncated" in str(e).lower()
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# FlowCollector — observation
# ---------------------------------------------------------------------------


class TestCollectorObserve:
    def test_single_observe(self) -> None:
        col = FlowCollector()
        key = col.observe(_pkt())
        assert col.active_count == 1
        assert key.protocol == 253

    def test_multiple_same_flow(self) -> None:
        col = FlowCollector()
        for _ in range(10):
            col.observe(_pkt())
        assert col.active_count == 1
        s = col.stats()
        assert s.total_observed == 10

    def test_different_flows(self) -> None:
        col = FlowCollector()
        col.observe(_pkt(src="64496-10.0.1.10"))
        col.observe(_pkt(src="64496-10.0.1.20"))
        col.observe(_pkt(src="64496-10.0.1.30"))
        assert col.active_count == 3

    def test_ports_distinguish_flows(self) -> None:
        col = FlowCollector()
        col.observe(_pkt(), src_port=80)
        col.observe(_pkt(), src_port=443)
        assert col.active_count == 2

    def test_protocol_distinguishes_flows(self) -> None:
        col = FlowCollector()
        col.observe(_pkt(proto=6))
        col.observe(_pkt(proto=17))
        assert col.active_count == 2

    def test_octets_tracked(self) -> None:
        col = FlowCollector()
        col.observe(_pkt())
        s = col.stats()
        # 28 header + len(b"test-flow") = 28 + 9 = 37
        assert s.total_octets == 37

    def test_ttl_minmax(self) -> None:
        col = FlowCollector()
        col.observe(_pkt(ttl=64))
        col.observe(_pkt(ttl=32))
        col.observe(_pkt(ttl=128))
        rec = col.get_flow(
            FlowKey(
                src_addr=IPv8Address.parse("64496-10.0.1.10"),
                dst_addr=IPv8Address.parse("64497-10.0.1.1"),
                protocol=253,
            )
        )
        assert rec is not None
        assert rec.min_ttl == 32
        assert rec.max_ttl == 128

    def test_tos_tracked(self) -> None:
        col = FlowCollector()
        col.observe(_pkt(tos=4))
        rec = col.get_flow(
            FlowKey(
                src_addr=IPv8Address.parse("64496-10.0.1.10"),
                dst_addr=IPv8Address.parse("64497-10.0.1.1"),
                protocol=253,
            )
        )
        assert rec is not None
        assert rec.tos == 4


# ---------------------------------------------------------------------------
# FlowCollector — export
# ---------------------------------------------------------------------------


class TestCollectorExport:
    def test_export_all(self) -> None:
        col = FlowCollector()
        col.observe(_pkt())
        records = col.export_all()
        assert len(records) == 1
        assert col.active_count == 0
        assert col.exported_count == 1

    def test_export_expired_idle(self) -> None:
        t = 0.0

        def clock() -> float:
            return t

        col = FlowCollector(idle_timeout=10.0, clock=clock)
        col.observe(_pkt())
        assert col.active_count == 1

        t = 5.0
        records = col.export_expired()
        assert len(records) == 0  # not expired yet

        t = 20.0
        records = col.export_expired()
        assert len(records) == 1
        assert col.active_count == 0

    def test_export_expired_active(self) -> None:
        t = 0.0

        def clock() -> float:
            return t

        col = FlowCollector(active_timeout=30.0, idle_timeout=100.0, clock=clock)
        col.observe(_pkt())

        # Keep refreshing (not idle), but active timeout hits
        for i in range(1, 10):
            t = float(i * 5)
            col.observe(_pkt())

        t = 50.0
        records = col.export_expired()
        assert len(records) == 1  # active timeout hit (50 - 0 > 30)

    def test_export_empty(self) -> None:
        col = FlowCollector()
        records = col.export_all()
        assert len(records) == 0

    def test_exported_records_property(self) -> None:
        col = FlowCollector()
        col.observe(_pkt())
        col.export_all()
        assert len(col.exported_records) == 1

    def test_flow_record_counters(self) -> None:
        col = FlowCollector()
        for _ in range(5):
            col.observe(_pkt())
        records = col.export_all()
        assert records[0].packets == 5
        assert records[0].octets == 5 * 37  # 37 bytes per packet


# ---------------------------------------------------------------------------
# Analytics
# ---------------------------------------------------------------------------


class TestAnalytics:
    def test_top_talkers(self) -> None:
        col = FlowCollector()
        # Flow A: 10 packets
        for _ in range(10):
            col.observe(_pkt(src="64496-10.0.1.10"))
        # Flow B: 20 packets
        for _ in range(20):
            col.observe(_pkt(src="64496-10.0.1.20"))
        top = col.top_talkers(2)
        assert len(top) == 2
        assert top[0].packets == 20  # highest first
        assert top[1].packets == 10

    def test_top_by_octets(self) -> None:
        col = FlowCollector()
        for _ in range(5):
            col.observe(_pkt(src="64496-10.0.1.10"))
        for _ in range(15):
            col.observe(_pkt(src="64496-10.0.1.20"))
        top = col.top_by_octets(1)
        assert len(top) == 1
        assert top[0].octets == 15 * 37

    def test_protocol_breakdown(self) -> None:
        col = FlowCollector()
        for _ in range(5):
            col.observe(_pkt(proto=6))
        for _ in range(3):
            col.observe(_pkt(proto=17))
        bd = col.protocol_breakdown()
        assert bd[6] == 5
        assert bd[17] == 3

    def test_protocol_breakdown_includes_exported(self) -> None:
        col = FlowCollector()
        for _ in range(5):
            col.observe(_pkt(proto=6))
        col.export_all()
        for _ in range(3):
            col.observe(_pkt(proto=6))
        bd = col.protocol_breakdown()
        assert bd[6] == 8  # 5 exported + 3 active


# ---------------------------------------------------------------------------
# Queries & state
# ---------------------------------------------------------------------------


class TestQueries:
    def test_get_flow(self) -> None:
        col = FlowCollector()
        key = col.observe(_pkt())
        rec = col.get_flow(key)
        assert rec is not None
        assert rec.packets == 1

    def test_get_flow_nonexistent(self) -> None:
        col = FlowCollector()
        key = FlowKey(
            src_addr=IPv8Address.parse("64496-10.0.1.99"),
            dst_addr=IPv8Address.parse("64497-10.0.1.1"),
            protocol=253,
        )
        assert col.get_flow(key) is None

    def test_stats(self) -> None:
        col = FlowCollector()
        col.observe(_pkt())
        col.observe(_pkt(src="64496-10.0.1.20"))
        s = col.stats()
        assert isinstance(s, CollectorStats)
        assert s.active_flows == 2
        assert s.total_observed == 2

    def test_to_dict(self) -> None:
        col = FlowCollector()
        col.observe(_pkt())
        d = col.to_dict()
        assert "stats" in d
        assert "active_flows" in d
        assert len(d["active_flows"]) == 1  # type: ignore[arg-type]

    def test_clear(self) -> None:
        col = FlowCollector()
        col.observe(_pkt())
        col.export_all()
        col.observe(_pkt())
        col.clear()
        assert col.active_count == 0
        assert col.exported_count == 0
        s = col.stats()
        assert s.total_observed == 0
