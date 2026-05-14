# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for ipv8lab.address."""

import pytest

from ipv8lab.address import (
    IPv8Address,
    asn_to_prefix,
    asn_to_prefix_str,
    prefix_str_to_asn,
    prefix_to_asn,
    validate_octet,
)
from ipv8lab.errors import InvalidAddressError, InvalidASNError, InvalidOctetError


# --- validate_octet -----------------------------------------------------------

class TestValidateOctet:
    def test_valid(self):
        assert validate_octet(0) == 0
        assert validate_octet(255) == 255
        assert validate_octet(128) == 128

    def test_negative(self):
        with pytest.raises(InvalidOctetError):
            validate_octet(-1)

    def test_too_large(self):
        with pytest.raises(InvalidOctetError):
            validate_octet(256)


# --- asn_to_prefix / prefix_to_asn -------------------------------------------

class TestASNConversion:
    def test_asn_64496(self):
        assert asn_to_prefix(64496) == (0, 0, 251, 240)

    def test_asn_64497(self):
        assert asn_to_prefix(64497) == (0, 0, 251, 241)

    def test_asn_zero(self):
        assert asn_to_prefix(0) == (0, 0, 0, 0)

    def test_asn_max(self):
        assert asn_to_prefix(4294967295) == (255, 255, 255, 255)

    def test_roundtrip(self):
        for asn in [0, 1, 256, 64496, 64497, 100000, 4294967295]:
            assert prefix_to_asn(asn_to_prefix(asn)) == asn

    def test_asn_to_prefix_str(self):
        assert asn_to_prefix_str(64496) == "0.0.251.240"

    def test_prefix_str_to_asn(self):
        assert prefix_str_to_asn("0.0.251.240") == 64496

    def test_invalid_asn_negative(self):
        with pytest.raises(InvalidASNError):
            asn_to_prefix(-1)

    def test_invalid_asn_too_large(self):
        with pytest.raises(InvalidASNError):
            asn_to_prefix(4294967296)


# --- IPv8Address.parse --------------------------------------------------------

class TestIPv8AddressParse:
    def test_asn_notation(self):
        addr = IPv8Address.parse("64496.192.0.2.1")
        assert addr.asn == 64496
        assert addr.routing_prefix == (0, 0, 251, 240)
        assert addr.host_part == (192, 0, 2, 1)
        assert addr.full_notation == "0.0.251.240.192.0.2.1"

    def test_full_notation(self):
        addr = IPv8Address.parse("0.0.251.240.192.0.2.1")
        assert addr.asn == 64496
        assert addr.routing_prefix == (0, 0, 251, 240)
        assert addr.host_part == (192, 0, 2, 1)

    def test_asn_notation_equals_full(self):
        a = IPv8Address.parse("64496.192.0.2.1")
        b = IPv8Address.parse("0.0.251.240.192.0.2.1")
        assert a == b

    def test_ipv4_compatible(self):
        addr = IPv8Address.parse("0.0.0.0.8.8.8.8")
        assert addr.is_ipv4_compatible()
        assert not addr.is_internal_zone()

    def test_internal_zone(self):
        addr = IPv8Address.parse("127.2.0.0.10.0.0.5")
        assert addr.is_internal_zone()
        assert not addr.is_ipv4_compatible()

    def test_asn_notation_64497(self):
        addr = IPv8Address.parse("64497.198.51.100.7")
        assert addr.asn == 64497
        assert addr.full_notation == "0.0.251.241.198.51.100.7"

    def test_invalid_part_count(self):
        with pytest.raises(InvalidAddressError):
            IPv8Address.parse("1.2.3")

    def test_invalid_octet_value(self):
        with pytest.raises(InvalidOctetError):
            IPv8Address.parse("0.0.0.0.999.0.0.0")

    def test_non_integer(self):
        with pytest.raises(InvalidAddressError):
            IPv8Address.parse("0.0.0.0.abc.0.0.0")

    def test_whitespace_stripped(self):
        addr = IPv8Address.parse("  64496.192.0.2.1  ")
        assert addr.asn == 64496


# --- IPv8Address properties ---------------------------------------------------

class TestIPv8AddressProperties:
    def test_asn_notation_property(self):
        addr = IPv8Address.parse("0.0.251.240.192.0.2.1")
        assert addr.asn_notation == "64496.192.0.2.1"

    def test_str(self):
        addr = IPv8Address.parse("64496.192.0.2.1")
        assert str(addr) == "0.0.251.240.192.0.2.1"

    def test_repr(self):
        addr = IPv8Address.parse("64496.192.0.2.1")
        assert repr(addr) == "IPv8Address(0.0.251.240.192.0.2.1)"


# --- IPv8Address int conversion -----------------------------------------------

class TestIPv8AddressInt:
    def test_to_int_and_back(self):
        addr = IPv8Address.parse("64496.192.0.2.1")
        val = addr.to_int()
        restored = IPv8Address.from_int(val)
        assert restored == addr

    def test_zero_address(self):
        addr = IPv8Address.parse("0.0.0.0.0.0.0.0")
        assert addr.to_int() == 0


# --- Address classes (Section 4) ----------------------------------------------

class TestAddressClasses:
    def test_ipv4_compatible(self):
        addr = IPv8Address.parse("0.0.0.0.8.8.8.8")
        assert addr.address_class == "ipv4-compatible"
        assert addr.is_ipv4_compatible()

    def test_asn_unicast(self):
        addr = IPv8Address.parse("64496.192.0.2.1")
        assert addr.address_class == "asn-unicast"
        assert addr.is_unicast()

    def test_internal_zone(self):
        addr = IPv8Address.parse("127.1.0.0.10.0.0.1")
        assert addr.address_class == "internal-zone"
        assert addr.is_internal_zone()
        assert not addr.is_unicast()

    def test_interop_prefix(self):
        addr = IPv8Address.parse("127.127.0.0.10.0.0.1")
        assert addr.is_interop_prefix()
        assert addr.is_internal_zone()  # 127.x is also internal

    def test_rine_peering(self):
        addr = IPv8Address.parse("100.0.0.1.10.0.0.1")
        assert addr.address_class == "rine-peering"
        assert addr.is_rine_prefix()
        assert not addr.is_unicast()

    def test_interior_link(self):
        addr = IPv8Address.parse("64496.222.0.0.1")
        assert addr.is_interior_link()

    def test_broadcast(self):
        addr = IPv8Address.parse("255.255.255.255.255.255.255.255")
        assert addr.address_class == "broadcast"
        assert addr.is_broadcast()
        assert not addr.is_unicast()

    def test_cross_asn_multicast(self):
        addr = IPv8Address.parse("255.255.0.0.224.0.0.1")
        assert addr.address_class == "cross-asn-multicast"
        assert addr.is_multicast()
        assert not addr.is_unicast()

    def test_intra_asn_multicast(self):
        addr = IPv8Address.parse("0.0.0.0.224.0.0.1")
        assert addr.address_class == "intra-asn-multicast"
        assert addr.is_intra_asn_multicast()

    def test_private_peering_asn(self):
        addr = IPv8Address.parse("65534.10.0.0.1")
        assert addr.is_private_peering_asn()
        assert addr.asn == 65534

    def test_documentation_asn(self):
        addr = IPv8Address.parse("65533.10.0.0.1")
        assert addr.is_documentation_asn()
        assert addr.asn == 65533

    def test_multicast_takes_precedence_over_broadcast(self):
        # ff.ff.ff.ff is broadcast, but ff.ff.00.00 is multicast
        mc = IPv8Address.parse("255.255.0.0.224.0.0.1")
        assert mc.address_class == "cross-asn-multicast"
        bc = IPv8Address.parse("255.255.255.255.0.0.0.0")
        assert bc.address_class == "broadcast"

    def test_ospf8_multicast(self):
        addr = IPv8Address.parse("255.255.0.1.224.0.0.5")
        assert addr.is_multicast()

    def test_bgp8_multicast(self):
        addr = IPv8Address.parse("255.255.0.2.224.0.0.1")
        assert addr.is_multicast()
