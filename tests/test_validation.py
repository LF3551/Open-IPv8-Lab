# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for prefix validation rules per draft-thain-ipv8-02."""

from ipv8lab.address import IPv8Address
from ipv8lab.validation import (
    RoutingScope,
    check_asn_reservation,
    check_egress,
    validate_prefix,
)


class TestValidatePrefix:
    def test_ipv4_compatible_is_global(self):
        addr = IPv8Address.parse("0.0.0.0.8.8.8.8")
        result = validate_prefix(addr)
        assert result.scope == RoutingScope.GLOBAL
        assert result.routable_externally is True

    def test_asn_unicast_is_global(self):
        addr = IPv8Address.parse("64496.192.0.2.1")
        result = validate_prefix(addr)
        assert result.scope == RoutingScope.GLOBAL
        assert result.routable_externally is True

    def test_internal_zone_not_routable_externally(self):
        addr = IPv8Address.parse("127.1.0.0.10.0.0.1")
        result = validate_prefix(addr)
        assert result.scope == RoutingScope.INTERNAL
        assert result.routable_externally is False

    def test_interop_is_internal(self):
        addr = IPv8Address.parse("127.127.0.0.10.0.0.1")
        result = validate_prefix(addr)
        assert result.scope == RoutingScope.INTERNAL

    def test_rine_is_peering(self):
        addr = IPv8Address.parse("100.0.0.1.10.0.0.1")
        result = validate_prefix(addr)
        assert result.scope == RoutingScope.PEERING
        assert result.routable_externally is False

    def test_private_peering_asn_65534(self):
        addr = IPv8Address.parse("0.0.255.254.10.0.0.1")
        result = validate_prefix(addr)
        assert result.scope == RoutingScope.PRIVATE
        assert result.routable_externally is False

    def test_documentation_asn_65533(self):
        addr = IPv8Address.parse("0.0.255.253.10.0.0.1")
        result = validate_prefix(addr)
        assert result.scope == RoutingScope.PRIVATE
        assert result.routable_externally is False

    def test_interior_link_not_external(self):
        addr = IPv8Address.parse("64496.222.0.0.1")
        result = validate_prefix(addr)
        assert result.scope == RoutingScope.INTERNAL
        assert result.routable_externally is False

    def test_broadcast_not_routable(self):
        addr = IPv8Address.parse("255.255.255.255.255.255.255.255")
        result = validate_prefix(addr)
        assert result.scope == RoutingScope.NOT_ROUTABLE

    def test_cross_asn_multicast_is_global(self):
        addr = IPv8Address.parse("255.255.0.0.224.0.0.1")
        result = validate_prefix(addr)
        assert result.scope == RoutingScope.GLOBAL

    def test_intra_asn_multicast_local_only(self):
        addr = IPv8Address.parse("0.0.0.0.224.0.0.1")
        result = validate_prefix(addr)
        assert result.scope == RoutingScope.LOCAL_ONLY
        assert result.routable_externally is False


class TestCheckEgress:
    def test_normal_unicast_no_violations(self):
        src = IPv8Address.parse("64496.192.0.2.1")
        dst = IPv8Address.parse("64497.198.51.100.7")
        assert check_egress(src, dst) == []

    def test_internal_zone_src_violation(self):
        src = IPv8Address.parse("127.1.0.0.10.0.0.1")
        dst = IPv8Address.parse("64497.198.51.100.7")
        violations = check_egress(src, dst)
        assert len(violations) == 1
        assert "127.x.x.x" in violations[0]

    def test_internal_zone_dst_violation(self):
        src = IPv8Address.parse("64496.192.0.2.1")
        dst = IPv8Address.parse("127.2.0.0.10.0.0.1")
        violations = check_egress(src, dst)
        assert len(violations) == 1

    def test_rine_src_violation(self):
        src = IPv8Address.parse("100.0.0.1.10.0.0.1")
        dst = IPv8Address.parse("64497.198.51.100.7")
        violations = check_egress(src, dst)
        assert len(violations) == 1
        assert "RINE" in violations[0]

    def test_rine_dst_violation(self):
        src = IPv8Address.parse("64496.192.0.2.1")
        dst = IPv8Address.parse("100.0.0.2.10.0.0.1")
        violations = check_egress(src, dst)
        assert len(violations) == 1

    def test_interior_link_violation(self):
        src = IPv8Address.parse("64496.222.0.0.1")
        dst = IPv8Address.parse("64497.198.51.100.7")
        violations = check_egress(src, dst)
        assert len(violations) == 1
        assert "interior link" in violations[0]

    def test_broadcast_dst_violation(self):
        src = IPv8Address.parse("64496.192.0.2.1")
        dst = IPv8Address.parse("255.255.255.255.255.255.255.255")
        violations = check_egress(src, dst)
        assert len(violations) == 1
        assert "broadcast" in violations[0]

    def test_multiple_violations(self):
        src = IPv8Address.parse("127.1.0.0.222.0.0.1")
        dst = IPv8Address.parse("100.0.0.1.10.0.0.1")
        violations = check_egress(src, dst)
        # src: internal zone + interior link; dst: RINE
        assert len(violations) == 3


class TestASNReservation:
    def test_normal_asn_ok(self):
        assert check_asn_reservation(64496) is None

    def test_internal_zone_asn_reserved(self):
        # 127.0.0.0 as 32-bit = 2130706432
        result = check_asn_reservation(2_130_706_432)
        assert result is not None
        assert "internal zone" in result

    def test_internal_zone_asn_max_reserved(self):
        result = check_asn_reservation(2_147_483_647)
        assert result is not None

    def test_rine_asn_reserved(self):
        # 100.0.0.0 as 32-bit = 1677721600
        result = check_asn_reservation(1_677_721_600)
        assert result is not None
        assert "RINE" in result

    def test_asn_zero_ok(self):
        assert check_asn_reservation(0) is None

    def test_asn_65534_reserved_for_private_peering(self):
        result = check_asn_reservation(65534)
        assert result is not None
        assert "private" in result.lower()

    def test_asn_65533_reserved_for_documentation(self):
        result = check_asn_reservation(65533)
        assert result is not None
        assert "documentation" in result.lower()
