# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for DNS A8 record per Section 7."""

import pytest

from ipv8lab.address import IPv8Address
from ipv8lab.dns_a8 import (
    A8Record,
    ZSRecord,
    ZSResolver,
    format_zone_line,
    format_zs_zone_line,
    is_even_odd_pair,
    make_even_odd_pair,
    validate_public_a8,
)


class TestA8Record:
    def test_to_wire_roundtrip(self):
        addr = IPv8Address.parse("64496.192.0.2.1")
        rec = A8Record(name="ns1.example.com.", address=addr)
        wire = rec.to_wire()
        assert len(wire) == 8
        restored = A8Record.from_wire("ns1.example.com.", wire)
        assert restored.address == addr

    def test_from_wire_bad_length(self):
        with pytest.raises(ValueError, match="8 bytes"):
            A8Record.from_wire("x.", b"\x00" * 4)

    def test_default_ttl(self):
        addr = IPv8Address.parse("64496.192.0.2.1")
        rec = A8Record(name="test.", address=addr)
        assert rec.ttl == 3600

    def test_custom_ttl(self):
        addr = IPv8Address.parse("64496.192.0.2.1")
        rec = A8Record(name="test.", address=addr, ttl=300)
        assert rec.ttl == 300


class TestEvenOddPair:
    def test_is_pair(self):
        a = IPv8Address.parse("64496.192.0.2.2")
        b = IPv8Address.parse("64496.192.0.2.3")
        assert is_even_odd_pair(a, b)

    def test_reversed_order(self):
        a = IPv8Address.parse("64496.192.0.2.3")
        b = IPv8Address.parse("64496.192.0.2.2")
        assert is_even_odd_pair(a, b)

    def test_not_pair_same_parity(self):
        a = IPv8Address.parse("64496.192.0.2.2")
        b = IPv8Address.parse("64496.192.0.2.4")
        assert not is_even_odd_pair(a, b)

    def test_not_pair_gap(self):
        a = IPv8Address.parse("64496.192.0.2.1")
        b = IPv8Address.parse("64496.192.0.2.4")
        assert not is_even_odd_pair(a, b)

    def test_make_from_even(self):
        base = IPv8Address.parse("64496.192.0.2.2")
        even, odd = make_even_odd_pair("ns.", base)
        assert is_even_odd_pair(even.address, odd.address)
        assert even.address.to_int() % 2 == 0
        assert odd.address.to_int() % 2 == 1

    def test_make_from_odd(self):
        base = IPv8Address.parse("64496.192.0.2.3")
        even, odd = make_even_odd_pair("ns.", base)
        assert is_even_odd_pair(even.address, odd.address)
        assert even.address.to_int() % 2 == 0


class TestValidatePublic:
    def test_public_address_ok(self):
        addr = IPv8Address.parse("64496.8.8.8.8")
        rec = A8Record(name="test.", address=addr)
        assert validate_public_a8(rec) == []

    def test_rfc1918_10(self):
        addr = IPv8Address.parse("64496.10.0.0.1")
        rec = A8Record(name="test.", address=addr)
        violations = validate_public_a8(rec)
        assert len(violations) == 1
        assert "RFC 1918" in violations[0]

    def test_rfc1918_172_16(self):
        addr = IPv8Address.parse("64496.172.16.0.1")
        rec = A8Record(name="test.", address=addr)
        assert len(validate_public_a8(rec)) == 1

    def test_rfc1918_192_168(self):
        addr = IPv8Address.parse("64496.192.168.1.1")
        rec = A8Record(name="test.", address=addr)
        assert len(validate_public_a8(rec)) == 1

    def test_non_private_172(self):
        addr = IPv8Address.parse("64496.172.32.0.1")
        rec = A8Record(name="test.", address=addr)
        assert validate_public_a8(rec) == []


class TestFormatZoneLine:
    def test_format(self):
        addr = IPv8Address.parse("64496.192.0.2.1")
        rec = A8Record(name="ns1.example.com.", address=addr, ttl=3600)
        line = format_zone_line(rec)
        assert "ns1.example.com." in line
        assert "IN" in line
        assert "A8" in line
        assert "64496" in line or "0.0.251.240" in line


class TestSpecExample:
    def test_example_addresses(self):
        """Section 7 example: ns1.example.com A8 records."""
        a1 = IPv8Address.parse("0.0.59.65.192.0.2.1")
        a2 = IPv8Address.parse("0.0.59.65.192.0.2.2")
        r1 = A8Record("ns1.example.com.", a1)
        r2 = A8Record("ns1.example.com.", a2)
        assert is_even_odd_pair(r1.address, r2.address) is False
        # .1 and .2 are odd+even but .1 is odd, .2 is even — they form a valid pair
        # Actually 1 is odd, 2 is even, diff=1, so reversed they are even=2, odd... no
        # 1 is odd so not even/odd pair starting from even
        # Correct: 1 & 2 differ by 1 but 1 is odd → not canonical even/odd pair


# ---------------------------------------------------------------------------
# ZSRecord
# ---------------------------------------------------------------------------

class TestZSRecord:
    def test_wire_roundtrip(self):
        rec = ZSRecord(name="64496.asn.arpa.", preference=10, target="zs1.example.com")
        wire = rec.to_wire()
        restored = ZSRecord.from_wire("64496.asn.arpa.", wire)
        assert restored.preference == 10
        assert restored.target == "zs1.example.com"

    def test_default_ttl(self):
        rec = ZSRecord(name="x.", preference=20, target="zs.example.com")
        assert rec.ttl == 3600

    def test_from_wire_too_short(self):
        with pytest.raises(ValueError, match="too short"):
            ZSRecord.from_wire("x.", b"\x00")

    def test_format_zone_line(self):
        rec = ZSRecord(name="64496.asn.arpa.", preference=10, target="zs1.example.com")
        line = format_zs_zone_line(rec)
        assert "ZS" in line
        assert "10" in line
        assert "zs1.example.com" in line


# ---------------------------------------------------------------------------
# ZSResolver lookup order (spec §3.4)
# ---------------------------------------------------------------------------

class TestZSResolver:
    def _resolver_with_primary(self, rn: int = 64496) -> ZSResolver:
        r = ZSResolver()
        r.add_zs(ZSRecord(f"{rn}.asn.arpa.", preference=10, target="zs1.example.com"))
        r.add_zs(ZSRecord(f"{rn}.asn.arpa.", preference=20, target="zs2.example.com"))
        return r

    def test_primary_wins(self):
        r = self._resolver_with_primary()
        result = r.lookup(64496)
        assert result.source == "asn.arpa"
        assert result.targets[0] == "zs1.example.com"
        assert len(result.targets) == 2

    def test_primary_sorted_by_preference(self):
        r = ZSResolver()
        r.add_zs(ZSRecord("64496.asn.arpa.", preference=30, target="zs3.example.com"))
        r.add_zs(ZSRecord("64496.asn.arpa.", preference=10, target="zs1.example.com"))
        result = r.lookup(64496)
        assert result.targets[0] == "zs1.example.com"

    def test_secondary_used_when_no_primary(self):
        r = ZSResolver()
        r.add_zs(ZSRecord("64496.asn.openipv8.org.", preference=10, target="zs.openipv8.org"))
        result = r.lookup(64496)
        assert result.source == "openipv8.org"
        assert result.targets == ["zs.openipv8.org"]

    def test_anycast_fallback(self):
        r = ZSResolver()
        addr = IPv8Address.parse("64496-10.0.0.254")
        r.add_a8(A8Record(name="anycast.64496.asn.arpa.", address=addr))
        result = r.lookup(64496)
        assert result.source == "anycast"
        assert len(result.targets) == 1

    def test_none_when_no_records(self):
        r = ZSResolver()
        result = r.lookup(64496)
        assert result.source == "none"
        assert result.targets == []
        assert result.records_used == []

    def test_primary_takes_precedence_over_secondary(self):
        r = ZSResolver()
        r.add_zs(ZSRecord("64496.asn.arpa.", preference=10, target="primary.example.com"))
        r.add_zs(ZSRecord("64496.asn.openipv8.org.", preference=5, target="secondary.example.com"))
        result = r.lookup(64496)
        assert result.source == "asn.arpa"
        assert result.targets[0] == "primary.example.com"

    def test_secondary_takes_precedence_over_anycast(self):
        r = ZSResolver()
        r.add_zs(ZSRecord("64496.asn.openipv8.org.", preference=10, target="secondary.example.com"))
        addr = IPv8Address.parse("64496-10.0.0.254")
        r.add_a8(A8Record(name="anycast.64496.asn.arpa.", address=addr))
        result = r.lookup(64496)
        assert result.source == "openipv8.org"

    def test_different_rn_isolated(self):
        r = ZSResolver()
        r.add_zs(ZSRecord("64496.asn.arpa.", preference=10, target="zs.example.com"))
        result = r.lookup(64497)
        assert result.source == "none"

    def test_zs_count(self):
        r = self._resolver_with_primary()
        assert r.zs_count == 2

    def test_a8_count(self):
        r = ZSResolver()
        addr = IPv8Address.parse("64496-10.0.0.254")
        r.add_a8(A8Record(name="anycast.64496.asn.arpa.", address=addr))
        assert r.a8_count == 1
