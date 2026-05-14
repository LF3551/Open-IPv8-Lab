# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for XLATE8 north-south traffic flow."""

from __future__ import annotations

from ipv8lab.address import IPv8Address
from ipv8lab.dns_a8 import A8Record
from ipv8lab.packet import IPv8Packet
from ipv8lab.xlate8_flow import DNS8Resolver, FlowEvent, NorthSouthFlow


class _FakeClock:
    def __init__(self, now: float = 1_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


# ---------------------------------------------------------------------------
# DNS8Resolver
# ---------------------------------------------------------------------------

class TestDNS8Resolver:
    def test_add_and_resolve(self) -> None:
        r = DNS8Resolver()
        addr = IPv8Address.parse("64496.10.0.1.100")
        r.add_record(A8Record(name="example.ipv8", address=addr))
        rec = r.resolve("example.ipv8")
        assert rec is not None
        assert rec.name == "example.ipv8"

    def test_resolve_missing(self) -> None:
        r = DNS8Resolver()
        assert r.resolve("nope.ipv8") is None

    def test_size(self) -> None:
        r = DNS8Resolver()
        assert r.size == 0
        addr = IPv8Address.parse("64496.10.0.1.100")
        r.add_record(A8Record(name="a.ipv8", address=addr))
        assert r.size == 1


# ---------------------------------------------------------------------------
# FlowEvent
# ---------------------------------------------------------------------------

class TestFlowEvent:
    def test_frozen(self) -> None:
        e = FlowEvent(step="dns_lookup", direction="egress", success=True, detail="ok")
        assert e.step == "dns_lookup"
        assert e.direction == "egress"
        assert e.success is True

    def test_default_detail(self) -> None:
        e = FlowEvent(step="x", direction="ingress", success=False)
        assert e.detail == ""


# ---------------------------------------------------------------------------
# DNS lookup step
# ---------------------------------------------------------------------------

class TestDNSLookup:
    def setup_method(self) -> None:
        self.clock = _FakeClock()
        self.flow = NorthSouthFlow(clock=self.clock)
        addr = IPv8Address.parse("64496.10.0.1.100")
        self.flow.dns.add_record(A8Record(name="service.ipv8", address=addr))

    def test_successful_lookup(self) -> None:
        rec = self.flow.dns_lookup("service.ipv8")
        assert rec is not None
        assert "service.ipv8" in rec.name

    def test_failed_lookup(self) -> None:
        rec = self.flow.dns_lookup("unknown.ipv8")
        assert rec is None

    def test_lookup_event(self) -> None:
        self.flow.dns_lookup("service.ipv8")
        evts = [e for e in self.flow.events if e.step == "dns_lookup"]
        assert len(evts) == 1
        assert evts[0].success is True

    def test_failed_lookup_event(self) -> None:
        self.flow.dns_lookup("unknown.ipv8")
        evts = [e for e in self.flow.events if e.step == "dns_lookup"]
        assert len(evts) == 1
        assert evts[0].success is False
        assert "NXDOMAIN" in evts[0].detail


# ---------------------------------------------------------------------------
# XLATE8 entry creation
# ---------------------------------------------------------------------------

class TestXLATECreate:
    def setup_method(self) -> None:
        self.clock = _FakeClock()
        self.flow = NorthSouthFlow(clock=self.clock)

    def test_create_entry(self) -> None:
        int_addr = IPv8Address.parse("127.1.0.0.10.0.1.10")
        ext_addr = IPv8Address.parse("64496.10.0.1.100")
        ok = self.flow.create_xlate_entry(int_addr, ext_addr, internal_port=8080, external_port=443)
        assert ok is True
        assert self.flow.xlate_table.size == 1

    def test_create_event(self) -> None:
        int_addr = IPv8Address.parse("127.1.0.0.10.0.1.10")
        ext_addr = IPv8Address.parse("64496.10.0.1.100")
        self.flow.create_xlate_entry(int_addr, ext_addr)
        evts = [e for e in self.flow.events if e.step == "xlate_create"]
        assert len(evts) == 1
        assert evts[0].success is True


# ---------------------------------------------------------------------------
# Egress translation
# ---------------------------------------------------------------------------

class TestEgressTranslation:
    def setup_method(self) -> None:
        self.clock = _FakeClock()
        self.flow = NorthSouthFlow(clock=self.clock)
        self.int_addr = IPv8Address.parse("127.1.0.0.10.0.1.10")
        self.ext_addr = IPv8Address.parse("64496.10.0.1.100")
        self.flow.create_xlate_entry(self.int_addr, self.ext_addr, internal_port=8080)

    def test_translate_rewrites_src(self) -> None:
        pkt = IPv8Packet(src=self.int_addr, dst=self.ext_addr, payload=b"data")
        result = self.flow.translate_egress(pkt, internal_port=8080)
        assert result is not None
        assert str(result.src) == str(self.ext_addr)
        assert str(result.dst) == str(self.ext_addr)

    def test_translate_no_entry_blocked(self) -> None:
        other = IPv8Address.parse("127.1.0.0.10.0.1.99")
        pkt = IPv8Packet(src=other, dst=self.ext_addr, payload=b"data")
        result = self.flow.translate_egress(pkt, internal_port=9999)
        assert result is None

    def test_translate_event(self) -> None:
        pkt = IPv8Packet(src=self.int_addr, dst=self.ext_addr, payload=b"data")
        self.flow.translate_egress(pkt, internal_port=8080)
        evts = [e for e in self.flow.events if e.step == "translate_egress"]
        assert len(evts) == 1
        assert evts[0].success is True

    def test_blocked_event(self) -> None:
        other = IPv8Address.parse("127.1.0.0.10.0.1.99")
        pkt = IPv8Packet(src=other, dst=self.ext_addr, payload=b"data")
        self.flow.translate_egress(pkt, internal_port=9999)
        evts = [e for e in self.flow.events if e.step == "translate_egress"]
        assert len(evts) == 1
        assert evts[0].success is False


# ---------------------------------------------------------------------------
# Full egress flow
# ---------------------------------------------------------------------------

class TestEgressFlow:
    def setup_method(self) -> None:
        self.clock = _FakeClock()
        self.flow = NorthSouthFlow(clock=self.clock)
        ext_addr = IPv8Address.parse("64496.10.0.1.100")
        self.flow.dns.add_record(A8Record(name="api.ipv8", address=ext_addr))

    def test_full_egress(self) -> None:
        int_addr = IPv8Address.parse("127.1.0.0.10.0.1.10")
        pkt = self.flow.egress_flow("api.ipv8", int_addr, internal_port=8080, external_port=443)
        assert pkt is not None
        # Source rewritten to external
        assert not str(pkt.src).startswith("127.")

    def test_egress_dns_fail(self) -> None:
        int_addr = IPv8Address.parse("127.1.0.0.10.0.1.10")
        pkt = self.flow.egress_flow("unknown.ipv8", int_addr)
        assert pkt is None

    def test_egress_events(self) -> None:
        int_addr = IPv8Address.parse("127.1.0.0.10.0.1.10")
        self.flow.egress_flow("api.ipv8", int_addr)
        steps = [e.step for e in self.flow.events]
        assert "dns_lookup" in steps
        assert "xlate_create" in steps
        assert "translate_egress" in steps


# ---------------------------------------------------------------------------
# Ingress translation
# ---------------------------------------------------------------------------

class TestIngressTranslation:
    def setup_method(self) -> None:
        self.clock = _FakeClock()
        self.flow = NorthSouthFlow(clock=self.clock)
        self.int_addr = IPv8Address.parse("127.1.0.0.10.0.1.10")
        self.ext_addr = IPv8Address.parse("64496.10.0.1.100")
        self.flow.create_xlate_entry(
            self.int_addr, self.ext_addr,
            internal_port=8080, external_port=443,
        )

    def test_reverse_translate(self) -> None:
        remote = IPv8Address.parse("64497.10.0.1.50")
        pkt = IPv8Packet(src=remote, dst=self.ext_addr, payload=b"response")
        result = self.flow.translate_ingress(pkt, external_port=443)
        assert result is not None
        assert str(result.dst) == str(self.int_addr)

    def test_no_reverse_entry(self) -> None:
        remote = IPv8Address.parse("64497.10.0.1.50")
        other_dst = IPv8Address.parse("64498.10.0.1.200")
        pkt = IPv8Packet(src=remote, dst=other_dst, payload=b"response")
        result = self.flow.translate_ingress(pkt, external_port=443)
        assert result is None

    def test_ingress_event(self) -> None:
        remote = IPv8Address.parse("64497.10.0.1.50")
        pkt = IPv8Packet(src=remote, dst=self.ext_addr, payload=b"response")
        self.flow.translate_ingress(pkt, external_port=443)
        evts = [e for e in self.flow.events if e.step == "translate_ingress"]
        assert len(evts) == 1
        assert evts[0].success is True


# ---------------------------------------------------------------------------
# Ingress flow
# ---------------------------------------------------------------------------

class TestIngressFlow:
    def setup_method(self) -> None:
        self.clock = _FakeClock()
        self.flow = NorthSouthFlow(clock=self.clock)
        self.int_addr = IPv8Address.parse("127.1.0.0.10.0.1.10")
        self.ext_addr = IPv8Address.parse("64496.10.0.1.100")
        self.flow.create_xlate_entry(self.int_addr, self.ext_addr, external_port=443)

    def test_full_ingress(self) -> None:
        remote = IPv8Address.parse("64497.10.0.1.50")
        pkt = self.flow.ingress_flow(remote, self.ext_addr, external_port=443)
        assert pkt is not None
        assert str(pkt.dst) == str(self.int_addr)

    def test_ingress_no_entry(self) -> None:
        remote = IPv8Address.parse("64497.10.0.1.50")
        other = IPv8Address.parse("64498.10.0.1.200")
        pkt = self.flow.ingress_flow(remote, other, external_port=443)
        assert pkt is None


# ---------------------------------------------------------------------------
# Round-trip
# ---------------------------------------------------------------------------

class TestRoundTrip:
    def setup_method(self) -> None:
        self.clock = _FakeClock()
        self.flow = NorthSouthFlow(clock=self.clock)
        ext_addr = IPv8Address.parse("64496.10.0.1.100")
        self.flow.dns.add_record(A8Record(name="web.ipv8", address=ext_addr))

    def test_full_round_trip(self) -> None:
        int_addr = IPv8Address.parse("127.1.0.0.10.0.1.10")
        egress, ingress = self.flow.round_trip(
            "web.ipv8", int_addr, internal_port=8080, external_port=443,
        )
        assert egress is not None
        assert ingress is not None
        # Ingress dst should be the external src (translated back)
        assert str(ingress.dst) == str(int_addr)

    def test_round_trip_dns_fail(self) -> None:
        int_addr = IPv8Address.parse("127.1.0.0.10.0.1.10")
        egress, ingress = self.flow.round_trip("unknown.ipv8", int_addr)
        assert egress is None
        assert ingress is None

    def test_round_trip_events(self) -> None:
        int_addr = IPv8Address.parse("127.1.0.0.10.0.1.10")
        self.flow.round_trip("web.ipv8", int_addr)
        steps = [e.step for e in self.flow.events]
        assert "dns_lookup" in steps
        assert "xlate_create" in steps
        assert "translate_egress" in steps
        assert "translate_ingress" in steps

    def test_all_events_passed(self) -> None:
        int_addr = IPv8Address.parse("127.1.0.0.10.0.1.10")
        self.flow.round_trip("web.ipv8", int_addr)
        assert self.flow.all_events_passed
        assert len(self.flow.failed_events) == 0


# ---------------------------------------------------------------------------
# Blocked without DNS
# ---------------------------------------------------------------------------

class TestNoDNSBlocked:
    def test_no_dns_no_xlate_blocked(self) -> None:
        """Section 1.4: no DNS lookup = no XLATE8 entry = blocked."""
        clock = _FakeClock()
        flow = NorthSouthFlow(clock=clock)
        # No DNS records registered — device tries to reach external
        int_addr = IPv8Address.parse("127.1.0.0.10.0.1.10")
        pkt = flow.egress_flow("blocked.ipv8", int_addr)
        assert pkt is None
        assert not flow.all_events_passed

    def test_direct_translate_without_xlate_blocked(self) -> None:
        """Translation without XLATE8 entry is blocked."""
        clock = _FakeClock()
        flow = NorthSouthFlow(clock=clock)
        int_addr = IPv8Address.parse("127.1.0.0.10.0.1.10")
        ext_addr = IPv8Address.parse("64496.10.0.1.100")
        pkt = IPv8Packet(src=int_addr, dst=ext_addr, payload=b"data")
        result = flow.translate_egress(pkt)
        assert result is None


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

class TestConfiguration:
    def test_zone_prefix(self) -> None:
        flow = NorthSouthFlow(zone_prefix="127.2.0.0")
        assert flow.zone_prefix == "127.2.0.0"

    def test_external_asn(self) -> None:
        flow = NorthSouthFlow(external_asn=64497)
        assert flow.external_asn == 64497

    def test_default_values(self) -> None:
        flow = NorthSouthFlow()
        assert flow.zone_prefix == "127.1.0.0"
        assert flow.external_asn == 64496
