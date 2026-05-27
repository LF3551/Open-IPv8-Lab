# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for ipv8lab.address."""

import pytest

from ipv8lab import address as address_module
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
        addr = IPv8Address.parse(" 64496.192.0.2.1 ")
        assert addr.asn == 64496


# --- IPv8Address properties ---------------------------------------------------

class TestIPv8AddressProperties:
    def test_asn_notation_property(self):
        addr = IPv8Address.parse("0.0.251.240.192.0.2.1")
        assert addr.asn_notation == "64496.192.0.2.1"

    def test_str(self):
        addr = IPv8Address.parse("64496.192.0.2.1")
        # Spec canonical hyphenated form (leading RN octet 0 → integer RN).
        assert str(addr) == "64496-192.0.2.1"

    def test_repr(self):
        addr = IPv8Address.parse("64496.192.0.2.1")
        assert repr(addr) == "IPv8Address(64496-192.0.2.1)"


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
        with pytest.warns(DeprecationWarning, match="127.127.0.0"):
            assert addr.is_interop_prefix()
        assert addr.is_internal_zone() # 127.x is also internal

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


# --- Hyphenated canonical form (spec §3.5) --------------------------------

class TestCanonicalHyphenated:
    def test_integer_rn_when_leading_octet_zero(self):
        addr = IPv8Address.parse("64496.192.0.2.1")
        assert addr.canonical == "64496-192.0.2.1"

    def test_dotted_rn_when_leading_octet_nonzero(self):
        addr = IPv8Address.parse("127.10.60.10.10.0.0.1")
        assert addr.canonical == "127.10.60.10-10.0.0.1"

    def test_ipv4_compatible_zero_rn(self):
        addr = IPv8Address.parse("0.0.0.0.8.8.8.8")
        assert addr.canonical == "0-8.8.8.8"

    def test_parse_hyphenated_integer_rn(self):
        addr = IPv8Address.parse("64496-192.0.2.1")
        assert addr.asn == 64496
        assert addr.host_part == (192, 0, 2, 1)

    def test_parse_hyphenated_dotted_rn(self):
        addr = IPv8Address.parse("127.10.60.10-10.0.0.1")
        assert addr.routing_prefix == (127, 10, 60, 10)
        assert addr.host_part == (10, 0, 0, 1)

    def test_parse_hyphenated_whitespace(self):
        addr = IPv8Address.parse(" 64496-192.0.2.1 ")
        assert addr.asn == 64496

    def test_parse_hyphenated_zero_rn(self):
        addr = IPv8Address.parse("0-8.8.8.8")
        assert addr.is_ipv4_compatible()
        assert addr.host_part == (8, 8, 8, 8)

    def test_three_forms_roundtrip_to_canonical(self):
        a = IPv8Address.parse("64496-192.0.2.1")
        b = IPv8Address.parse("64496.192.0.2.1")
        c = IPv8Address.parse("0.0.251.240.192.0.2.1")
        assert a == b == c
        assert a.canonical == b.canonical == c.canonical == "64496-192.0.2.1"

    def test_parse_rejects_double_hyphen(self):
        with pytest.raises(InvalidAddressError):
            IPv8Address.parse("64496-192-0.2.1")

    def test_parse_rejects_empty_components(self):
        with pytest.raises(InvalidAddressError):
            IPv8Address.parse("-192.0.2.1")
        with pytest.raises(InvalidAddressError):
            IPv8Address.parse("64496-")

    def test_parse_rejects_bad_la_length(self):
        with pytest.raises(InvalidAddressError):
            IPv8Address.parse("64496-192.0.2")

    def test_parse_rejects_bad_rn_dotted_length(self):
        with pytest.raises(InvalidAddressError):
            IPv8Address.parse("127.10.60-10.0.0.1")

    def test_parse_rejects_octet_out_of_range(self):
        with pytest.raises(InvalidOctetError):
            IPv8Address.parse("64496-300.0.0.0")
        with pytest.raises(InvalidOctetError):
            IPv8Address.parse("127.10.999.10-10.0.0.1")

    def test_parse_rejects_rn_above_max(self):
        with pytest.raises(InvalidASNError):
            IPv8Address.parse(f"{4_294_967_296}-10.0.0.1")

    def test_parse_rejects_non_integer_rn(self):
        with pytest.raises(InvalidAddressError):
            IPv8Address.parse("abc-10.0.0.1")


class TestASNSimplificationFlag:
    def test_default_is_true(self):
        assert address_module.ASN_SIMPLIFICATION is True

    def test_flag_false_forces_dotted_rn(self, monkeypatch):
        monkeypatch.setattr(address_module, "ASN_SIMPLIFICATION", False)
        addr = IPv8Address.parse("64496-192.0.2.1")
        assert addr.canonical == "0.0.251.240-192.0.2.1"

    def test_flag_false_leaves_nonzero_rn_dotted(self, monkeypatch):
        monkeypatch.setattr(address_module, "ASN_SIMPLIFICATION", False)
        addr = IPv8Address.parse("127.10.60.10-10.0.0.1")
        assert addr.canonical == "127.10.60.10-10.0.0.1"

    def test_flag_does_not_affect_wire_int(self):
        addr = IPv8Address.parse("64496-192.0.2.1")
        wire = addr.to_int()
        assert IPv8Address.from_int(wire) == addr


class TestSpec06Aliases:
    def test_rn_is_alias_of_asn(self):
        addr = IPv8Address.parse("64496-192.0.2.1")
        assert addr.rn == addr.asn == 64496

    def test_rn_octets_is_alias_of_routing_prefix(self):
        addr = IPv8Address.parse("127.10.60.10-10.0.0.1")
        assert addr.rn_octets == addr.routing_prefix == (127, 10, 60, 10)

    def test_la_octets_is_alias_of_host_part(self):
        addr = IPv8Address.parse("127.10.60.10-10.0.0.1")
        assert addr.la_octets == addr.host_part == (10, 0, 0, 1)

    def test_dotted_notation_alias(self):
        addr = IPv8Address.parse("64496-192.0.2.1")
        assert addr.dotted_notation == addr.full_notation == "0.0.251.240.192.0.2.1"

    def test_la_str_alias(self):
        addr = IPv8Address.parse("64496-192.0.2.1")
        assert addr.la_str == addr.host_str == "192.0.2.1"

    def test_rn_str_always_dotted(self):
        addr = IPv8Address.parse("64496-192.0.2.1")
        assert addr.rn_str == "0.0.251.240"


# --- Reserved block table (spec §4.4) ----------------------------------------

class TestReservedBlockTable:
    # super-scalar: leading octet 1–32
    def test_super_scalar_octet_1(self):
        addr = IPv8Address.parse("1.0.0.1-10.0.0.1")
        assert addr.is_super_scalar()
        assert not addr.is_iana_reserved()

    def test_super_scalar_octet_32(self):
        addr = IPv8Address.parse("536870912-10.0.0.1")  # 32 << 24
        assert addr.is_super_scalar()

    def test_not_super_scalar_octet_0(self):
        assert not IPv8Address.parse("64496-10.0.0.1").is_super_scalar()

    def test_not_super_scalar_octet_33(self):
        addr = IPv8Address.parse("553648128-10.0.0.1")  # 33 << 24
        assert not addr.is_super_scalar()
        assert addr.is_iana_reserved()

    # RIR sub-RN: leading octet 110–119
    def test_rir_sub_rn_arin(self):
        addr = IPv8Address.parse("110.0.0.1-10.0.0.1")
        assert addr.is_rir_sub_rn()
        assert addr.rir == "ARIN"

    def test_rir_sub_rn_ripe(self):
        addr = IPv8Address.parse("111.0.0.1-10.0.0.1")
        assert addr.is_rir_sub_rn()
        assert addr.rir == "RIPE"

    def test_rir_sub_rn_apnic(self):
        addr = IPv8Address.parse("112.0.0.1-10.0.0.1")
        assert addr.rir == "APNIC"

    def test_rir_sub_rn_lacnic(self):
        addr = IPv8Address.parse("113.0.0.1-10.0.0.1")
        assert addr.rir == "LACNIC"

    def test_rir_sub_rn_afrinic(self):
        addr = IPv8Address.parse("114.0.0.1-10.0.0.1")
        assert addr.rir == "AFRINIC"

    def test_rir_sub_rn_future(self):
        addr = IPv8Address.parse("115.0.0.1-10.0.0.1")
        assert addr.is_rir_sub_rn()
        assert addr.rir is None  # 115–119 reserved, no name yet

    def test_not_rir_sub_rn(self):
        assert not IPv8Address.parse("64496-10.0.0.1").is_rir_sub_rn()
        assert IPv8Address.parse("64496-10.0.0.1").rir is None

    # cellular carrier: leading octet 128–130
    def test_cellular_carrier_128(self):
        addr = IPv8Address.parse("128.0.0.1-10.0.0.1")
        assert addr.is_cellular_carrier()
        assert not addr.is_iana_reserved()

    def test_cellular_carrier_130(self):
        addr = IPv8Address.parse("130.0.0.1-10.0.0.1")
        assert addr.is_cellular_carrier()

    def test_not_cellular_carrier_127(self):
        assert not IPv8Address.parse("127.10.60.10-10.0.0.1").is_cellular_carrier()

    def test_not_cellular_carrier_131(self):
        addr = IPv8Address.parse("131.0.0.1-10.0.0.1")
        assert not addr.is_cellular_carrier()
        assert addr.is_iana_reserved()

    # IANA reserved gaps
    def test_iana_reserved_gap_33_99(self):
        assert IPv8Address.parse("33.0.0.1-10.0.0.1").is_iana_reserved()
        assert IPv8Address.parse("99.0.0.1-10.0.0.1").is_iana_reserved()

    def test_iana_reserved_gap_101_109(self):
        assert IPv8Address.parse("101.0.0.1-10.0.0.1").is_iana_reserved()
        assert IPv8Address.parse("109.0.0.1-10.0.0.1").is_iana_reserved()

    def test_iana_reserved_gap_120_126(self):
        assert IPv8Address.parse("120.0.0.1-10.0.0.1").is_iana_reserved()
        assert IPv8Address.parse("126.0.0.1-10.0.0.1").is_iana_reserved()

    def test_iana_reserved_gap_131_221(self):
        assert IPv8Address.parse("131.0.0.1-10.0.0.1").is_iana_reserved()
        assert IPv8Address.parse("221.0.0.1-10.0.0.1").is_iana_reserved()

    def test_iana_reserved_gap_223_254(self):
        assert IPv8Address.parse("223.0.0.1-10.0.0.1").is_iana_reserved()
        assert IPv8Address.parse("254.0.0.1-10.0.0.1").is_iana_reserved()

    # well-known non-reserved octets must NOT be IANA-reserved
    def test_not_iana_reserved_0(self):
        assert not IPv8Address.parse("0-10.0.0.1").is_iana_reserved()

    def test_not_iana_reserved_100_rine(self):
        assert not IPv8Address.parse("100.0.0.1-10.0.0.1").is_iana_reserved()

    def test_not_iana_reserved_127_internal(self):
        assert not IPv8Address.parse("127.1.0.0-10.0.0.1").is_iana_reserved()

    def test_not_iana_reserved_255_broadcast(self):
        assert not IPv8Address.parse("255.255.255.255.255.255.255.255").is_iana_reserved()


class TestInteropPrefixDeprecation:
    def test_is_interop_prefix_emits_deprecation(self):
        addr = IPv8Address.parse("127.127.0.0-10.0.0.1")
        with pytest.warns(DeprecationWarning):
            result = addr.is_interop_prefix()
        assert result is True

    def test_non_interop_also_warns(self):
        addr = IPv8Address.parse("127.1.0.0-10.0.0.1")
        with pytest.warns(DeprecationWarning):
            result = addr.is_interop_prefix()
        assert result is False
