# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for NAT8 gateway module."""

from __future__ import annotations


from ipv8lab.address import IPv8Address
from ipv8lab.nat8 import (
    NATGateway,
    NATMapping,
    NATMode,
)
from ipv8lab.packet import IPv8Packet


def _pkt(src: str = "127.1.0.0.10.0.1.10", dst: str = "64497-10.0.1.1") -> IPv8Packet:
    return IPv8Packet(
        src=IPv8Address.parse(src),
        dst=IPv8Address.parse(dst),
        payload=b"nat-test",
    )


# ---------------------------------------------------------------------------
# Static NAT
# ---------------------------------------------------------------------------

class TestStaticNAT:
    def test_add_mapping(self) -> None:
        gw = NATGateway(mode=NATMode.STATIC)
        m = gw.add_static_mapping("127.1.0.0.10.0.1.10", "64496-10.0.1.100")
        assert isinstance(m, NATMapping)
        assert gw.mapping_count == 1

    def test_egress(self) -> None:
        gw = NATGateway(mode=NATMode.STATIC)
        gw.add_static_mapping("127.1.0.0.10.0.1.10", "64496-10.0.1.100")
        result = gw.translate_egress(_pkt())
        assert result is not None
        assert str(result.src) == str(IPv8Address.parse("64496-10.0.1.100"))
        assert result.dst == _pkt().dst

    def test_ingress(self) -> None:
        gw = NATGateway(mode=NATMode.STATIC)
        gw.add_static_mapping("127.1.0.0.10.0.1.10", "64496-10.0.1.100")
        pkt_in = _pkt(src="64497-10.0.1.1", dst="64496-10.0.1.100")
        result = gw.translate_ingress(pkt_in)
        assert result is not None
        assert str(result.dst) == str(IPv8Address.parse("127.1.0.0.10.0.1.10"))

    def test_egress_no_mapping(self) -> None:
        gw = NATGateway(mode=NATMode.STATIC)
        result = gw.translate_egress(_pkt())
        assert result is None

    def test_ingress_no_mapping(self) -> None:
        gw = NATGateway(mode=NATMode.STATIC)
        result = gw.translate_ingress(_pkt(src="64497-10.0.1.1", dst="64496-10.0.1.100"))
        assert result is None

    def test_roundtrip(self) -> None:
        gw = NATGateway(mode=NATMode.STATIC)
        gw.add_static_mapping("127.1.0.0.10.0.1.10", "64496-10.0.1.100")
        out = gw.translate_egress(_pkt())
        assert out is not None
        reply = _pkt(src="64497-10.0.1.1", dst=str(out.src))
        back = gw.translate_ingress(reply)
        assert back is not None
        assert str(back.dst) == str(IPv8Address.parse("127.1.0.0.10.0.1.10"))

    def test_multiple_mappings(self) -> None:
        gw = NATGateway(mode=NATMode.STATIC)
        gw.add_static_mapping("127.1.0.0.10.0.1.10", "64496-10.0.1.100")
        gw.add_static_mapping("127.1.0.0.10.0.1.11", "64496-10.0.1.101")
        assert gw.mapping_count == 2

    def test_payload_preserved(self) -> None:
        gw = NATGateway(mode=NATMode.STATIC)
        gw.add_static_mapping("127.1.0.0.10.0.1.10", "64496-10.0.1.100")
        result = gw.translate_egress(_pkt())
        assert result is not None
        assert result.payload == b"nat-test"

    def test_stats(self) -> None:
        gw = NATGateway(mode=NATMode.STATIC)
        gw.add_static_mapping("127.1.0.0.10.0.1.10", "64496-10.0.1.100")
        gw.translate_egress(_pkt())
        gw.translate_egress(_pkt())
        s = gw.stats()
        assert s.total_egress == 2
        assert s.active_mappings == 1


# ---------------------------------------------------------------------------
# Dynamic NAT
# ---------------------------------------------------------------------------

class TestDynamicNAT:
    def test_auto_allocate(self) -> None:
        gw = NATGateway(mode=NATMode.DYNAMIC)
        gw.add_pool_address("64496-10.0.1.200")
        result = gw.translate_egress(_pkt())
        assert result is not None
        assert gw.mapping_count == 1

    def test_pool_exhausted(self) -> None:
        gw = NATGateway(mode=NATMode.DYNAMIC)
        gw.add_pool_address("64496-10.0.1.200")
        gw.translate_egress(_pkt(src="127.1.0.0.10.0.1.10"))
        result = gw.translate_egress(_pkt(src="127.1.0.0.10.0.1.11"))
        assert result is None  # pool exhausted

    def test_reuses_mapping(self) -> None:
        gw = NATGateway(mode=NATMode.DYNAMIC)
        gw.add_pool_address("64496-10.0.1.200")
        r1 = gw.translate_egress(_pkt())
        r2 = gw.translate_egress(_pkt())
        assert r1 is not None and r2 is not None
        assert str(r1.src) == str(r2.src)
        assert gw.mapping_count == 1

    def test_pool_available(self) -> None:
        gw = NATGateway(mode=NATMode.DYNAMIC)
        gw.add_pool_address("64496-10.0.1.200")
        gw.add_pool_address("64496-10.0.1.201")
        assert gw.pool_available == 2
        gw.translate_egress(_pkt())
        assert gw.pool_available == 1

    def test_release(self) -> None:
        gw = NATGateway(mode=NATMode.DYNAMIC)
        gw.add_pool_address("64496-10.0.1.200")
        gw.translate_egress(_pkt())
        assert gw.pool_available == 0
        gw.release("127.1.0.0.10.0.1.10")
        assert gw.pool_available == 1
        assert gw.mapping_count == 0

    def test_release_nonexistent(self) -> None:
        gw = NATGateway(mode=NATMode.DYNAMIC)
        assert gw.release("127.1.0.0.10.0.1.99") is False

    def test_expiry(self) -> None:
        t = 0.0

        def clock() -> float:
            return t

        gw = NATGateway(mode=NATMode.DYNAMIC, idle_timeout=10.0, clock=clock)
        gw.add_pool_address("64496-10.0.1.200")
        gw.translate_egress(_pkt())
        assert gw.mapping_count == 1
        t = 20.0  # past timeout
        gw.translate_egress(_pkt(src="127.1.0.0.10.0.1.99"))  # triggers expire
        # old mapping expired, new one created
        assert gw.mapping_count == 1

    def test_multiple_hosts(self) -> None:
        gw = NATGateway(mode=NATMode.DYNAMIC)
        for i in range(5):
            gw.add_pool_address(f"64496.10.0.1.{200 + i}")
        for i in range(5):
            gw.translate_egress(_pkt(src=f"127.1.0.0.10.0.1.{10 + i}"))
        assert gw.mapping_count == 5
        assert gw.pool_available == 0


# ---------------------------------------------------------------------------
# PAT
# ---------------------------------------------------------------------------

class TestPAT:
    def test_pat_egress(self) -> None:
        gw = NATGateway(mode=NATMode.PAT, pat_address="64496-10.0.1.50")
        result = gw.translate_egress(_pkt(), src_port=8080)
        assert result is not None
        assert str(result.src) == str(IPv8Address.parse("64496-10.0.1.50"))

    def test_pat_ingress(self) -> None:
        gw = NATGateway(mode=NATMode.PAT, pat_address="64496-10.0.1.50")
        gw.translate_egress(_pkt(), src_port=8080)
        m = gw.get_pat_mapping("127.1.0.0.10.0.1.10", 8080)
        assert m is not None
        reply = _pkt(src="64497-10.0.1.1", dst="64496-10.0.1.50")
        result = gw.translate_ingress(reply, dst_port=m.external_port)
        assert result is not None
        assert str(result.dst) == str(IPv8Address.parse("127.1.0.0.10.0.1.10"))

    def test_pat_multiple_ports(self) -> None:
        gw = NATGateway(mode=NATMode.PAT, pat_address="64496-10.0.1.50")
        for port in range(8080, 8090):
            gw.translate_egress(_pkt(), src_port=port)
        assert gw.mapping_count == 10

    def test_pat_different_hosts(self) -> None:
        gw = NATGateway(mode=NATMode.PAT, pat_address="64496-10.0.1.50")
        gw.translate_egress(_pkt(src="127.1.0.0.10.0.1.10"), src_port=80)
        gw.translate_egress(_pkt(src="127.1.0.0.10.0.1.11"), src_port=80)
        assert gw.mapping_count == 2

    def test_pat_no_addr(self) -> None:
        gw = NATGateway(mode=NATMode.PAT)
        result = gw.translate_egress(_pkt(), src_port=80)
        assert result is None

    def test_pat_release(self) -> None:
        gw = NATGateway(mode=NATMode.PAT, pat_address="64496-10.0.1.50")
        gw.translate_egress(_pkt(), src_port=8080)
        assert gw.release_pat("127.1.0.0.10.0.1.10", 8080)
        assert gw.mapping_count == 0

    def test_pat_release_nonexistent(self) -> None:
        gw = NATGateway(mode=NATMode.PAT, pat_address="64496-10.0.1.50")
        assert gw.release_pat("127.1.0.0.10.0.1.99", 9999) is False

    def test_pat_reuse_mapping(self) -> None:
        gw = NATGateway(mode=NATMode.PAT, pat_address="64496-10.0.1.50")
        gw.translate_egress(_pkt(), src_port=8080)
        gw.translate_egress(_pkt(), src_port=8080)
        assert gw.mapping_count == 1
        m = gw.get_pat_mapping("127.1.0.0.10.0.1.10", 8080)
        assert m is not None
        assert m.packets_out == 2

    def test_pat_expiry(self) -> None:
        t = 0.0

        def clock() -> float:
            return t

        gw = NATGateway(mode=NATMode.PAT, pat_address="64496-10.0.1.50",
                        idle_timeout=10.0, clock=clock)
        gw.translate_egress(_pkt(), src_port=8080)
        assert gw.mapping_count == 1
        t = 20.0
        gw.translate_egress(_pkt(src="127.1.0.0.10.0.1.99"), src_port=9090)
        # old expired, new created
        assert gw.mapping_count == 1


# ---------------------------------------------------------------------------
# Stats & serialization
# ---------------------------------------------------------------------------

class TestStatsAndSerialization:
    def test_stats_drops(self) -> None:
        gw = NATGateway(mode=NATMode.STATIC)
        gw.translate_egress(_pkt())  # no mapping → drop
        s = gw.stats()
        assert s.total_dropped == 1

    def test_to_dict(self) -> None:
        gw = NATGateway(mode=NATMode.STATIC)
        gw.add_static_mapping("127.1.0.0.10.0.1.10", "64496-10.0.1.100")
        d = gw.to_dict()
        assert d["mode"] == "static"
        assert len(d["mappings"]) == 1  # type: ignore[arg-type]

    def test_clear(self) -> None:
        gw = NATGateway(mode=NATMode.STATIC)
        gw.add_static_mapping("127.1.0.0.10.0.1.10", "64496-10.0.1.100")
        gw.translate_egress(_pkt())
        gw.clear()
        assert gw.mapping_count == 0
        assert gw.stats().total_egress == 0

    def test_mapping_to_dict(self) -> None:
        gw = NATGateway(mode=NATMode.STATIC)
        m = gw.add_static_mapping("127.1.0.0.10.0.1.10", "64496-10.0.1.100")
        d = m.to_dict()
        assert d["mode"] == "static"
        assert "internal_addr" in d

    def test_all_mappings(self) -> None:
        gw = NATGateway(mode=NATMode.STATIC)
        gw.add_static_mapping("127.1.0.0.10.0.1.10", "64496-10.0.1.100")
        gw.add_static_mapping("127.1.0.0.10.0.1.11", "64496-10.0.1.101")
        assert len(gw.all_mappings()) == 2

    def test_get_mapping(self) -> None:
        gw = NATGateway(mode=NATMode.STATIC)
        gw.add_static_mapping("127.1.0.0.10.0.1.10", "64496-10.0.1.100")
        assert gw.get_mapping("127.1.0.0.10.0.1.10") is not None
        assert gw.get_mapping("127.1.0.0.10.0.1.99") is None
