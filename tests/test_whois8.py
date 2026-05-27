# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for WHOIS8 mock resolver."""

import pytest

from ipv8lab.address import IPv8Address
from ipv8lab.whois8 import (
    ValidationStatus,
    WHOIS8Record,
    WHOIS8Resolver,
)


@pytest.fixture()
def resolver() -> WHOIS8Resolver:
    r = WHOIS8Resolver()
    r.register(WHOIS8Record(asn=64496, holder="Example-A", country="US"))
    r.register(WHOIS8Record(asn=64497, holder="Example-B", country="GB"))
    return r


class TestWHOIS8Record:
    def test_prefix_str(self):
        rec = WHOIS8Record(asn=64496, holder="Example-A")
        assert rec.prefix_str == "0.0.251.240"

    def test_default_active(self):
        rec = WHOIS8Record(asn=64496, holder="Test")
        assert rec.active is True

    def test_default_prefix_min(self):
        rec = WHOIS8Record(asn=64496, holder="Test")
        assert rec.prefix_min == 16


class TestRegister:
    def test_register_and_lookup(self, resolver: WHOIS8Resolver):
        rec = resolver.lookup(64496)
        assert rec is not None
        assert rec.holder == "Example-A"

    def test_lookup_missing(self, resolver: WHOIS8Resolver):
        assert resolver.lookup(99999) is None

    def test_register_reserved_internal_zone(self):
        r = WHOIS8Resolver()
        with pytest.raises(ValueError, match="internal zone"):
            r.register(WHOIS8Record(asn=2130706432, holder="Bad"))

    def test_register_reserved_rine(self):
        r = WHOIS8Resolver()
        with pytest.raises(ValueError, match="RINE"):
            r.register(WHOIS8Record(asn=1677721600, holder="Bad"))

    def test_register_reserved_private_peering(self):
        r = WHOIS8Resolver()
        with pytest.raises(ValueError, match="private peering"):
            r.register(WHOIS8Record(asn=65534, holder="Bad"))

    def test_register_reserved_documentation(self):
        r = WHOIS8Resolver()
        with pytest.raises(ValueError, match="documentation"):
            r.register(WHOIS8Record(asn=65533, holder="Bad"))

    def test_unregister(self, resolver: WHOIS8Resolver):
        resolver.unregister(64496)
        assert resolver.lookup(64496) is None

    def test_unregister_missing(self, resolver: WHOIS8Resolver):
        with pytest.raises(KeyError, match="not in registry"):
            resolver.unregister(99999)

    def test_list_asns(self, resolver: WHOIS8Resolver):
        assert resolver.list_asns() == [64496, 64497]

    def test_len(self, resolver: WHOIS8Resolver):
        assert len(resolver) == 2


class TestValidateRoute:
    def test_valid_route(self, resolver: WHOIS8Resolver):
        result = resolver.validate_route(64496, prefix_length=8)
        assert result.is_valid
        assert result.status == ValidationStatus.VALID
        assert result.record is not None

    def test_unknown_asn(self, resolver: WHOIS8Resolver):
        result = resolver.validate_route(99999)
        assert not result.is_valid
        assert result.status == ValidationStatus.UNKNOWN_ASN

    def test_reserved_range(self, resolver: WHOIS8Resolver):
        result = resolver.validate_route(2130706432)
        assert result.status == ValidationStatus.RESERVED_RANGE

    def test_expired_record(self):
        r = WHOIS8Resolver()
        r.register(WHOIS8Record(asn=64496, holder="X", active=True))
        # Simulate expiration by re-registering inactive
        r._registry[64496] = WHOIS8Record(asn=64496, holder="X", active=False)
        result = r.validate_route(64496)
        assert result.status == ValidationStatus.EXPIRED

    def test_prefix_too_specific(self, resolver: WHOIS8Resolver):
        result = resolver.validate_route(64496, prefix_length=24)
        assert result.status == ValidationStatus.PREFIX_TOO_SPECIFIC

    def test_prefix_exactly_16(self, resolver: WHOIS8Resolver):
        result = resolver.validate_route(64496, prefix_length=16)
        assert result.is_valid

    def test_prefix_8(self, resolver: WHOIS8Resolver):
        result = resolver.validate_route(64496, prefix_length=8)
        assert result.is_valid


class TestValidateDestination:
    def test_valid_destination(self, resolver: WHOIS8Resolver):
        addr = IPv8Address.parse("64496-192.0.2.1")
        result = resolver.validate_destination(addr)
        assert result.is_valid

    def test_unknown_destination(self, resolver: WHOIS8Resolver):
        addr = IPv8Address.parse("12345.10.0.0.1")
        result = resolver.validate_destination(addr)
        assert result.status == ValidationStatus.UNKNOWN_ASN

    def test_ipv4_compatible_bypass(self, resolver: WHOIS8Resolver):
        addr = IPv8Address.parse("0.0.0.0.8.8.8.8")
        result = resolver.validate_destination(addr)
        assert result.is_valid
        assert "IPv4" in result.reason

    def test_internal_zone_rejected(self, resolver: WHOIS8Resolver):
        addr = IPv8Address.parse("127.1.0.0.10.0.0.1")
        result = resolver.validate_destination(addr)
        assert result.status == ValidationStatus.RESERVED_RANGE

    def test_rine_rejected(self, resolver: WHOIS8Resolver):
        addr = IPv8Address.parse("100.0.0.1.10.0.0.1")
        result = resolver.validate_destination(addr)
        assert result.status == ValidationStatus.RESERVED_RANGE

    def test_expired_destination(self):
        r = WHOIS8Resolver()
        r._registry[64496] = WHOIS8Record(asn=64496, holder="X", active=False)
        addr = IPv8Address.parse("64496-192.0.2.1")
        result = r.validate_destination(addr)
        assert result.status == ValidationStatus.EXPIRED
