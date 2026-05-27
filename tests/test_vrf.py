# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for VRF per Section 8.8."""

import pytest

from ipv8lab.address import IPv8Address
from ipv8lab.route import Route
from ipv8lab.vrf import (
    DEFAULT_VRF_NAME,
    MGMT_VLAN,
    MGMT_VRF_NAME,
    OOB_VLAN,
    OOB_VRF_NAME,
    VRF,
    VRFManager,
    ipv8_vrf_name,
    ipv8_vrf_rd,
)


class TestMandatoryVRFs:
    def test_management_vrf_exists(self):
        mgr = VRFManager()
        assert mgr.get(MGMT_VRF_NAME) is not None

    def test_oob_vrf_exists(self):
        mgr = VRFManager()
        assert mgr.get(OOB_VRF_NAME) is not None

    def test_default_vrf_exists(self):
        mgr = VRFManager()
        assert mgr.get(DEFAULT_VRF_NAME) is not None

    def test_mgmt_vlan_4090(self):
        mgr = VRFManager()
        assert mgr.management.vlan == MGMT_VLAN

    def test_oob_vlan_4091(self):
        mgr = VRFManager()
        assert mgr.oob.vlan == OOB_VLAN

    def test_cannot_delete_management(self):
        mgr = VRFManager()
        with pytest.raises(ValueError, match="mandatory"):
            mgr.delete(MGMT_VRF_NAME)

    def test_cannot_delete_oob(self):
        mgr = VRFManager()
        with pytest.raises(ValueError, match="mandatory"):
            mgr.delete(OOB_VRF_NAME)


class TestVRFCreation:
    def test_create_custom(self):
        mgr = VRFManager()
        vrf = mgr.create("customer-a", vlan=100)
        assert vrf.name == "customer-a"
        assert vrf.vlan == 100

    def test_create_duplicate(self):
        mgr = VRFManager()
        mgr.create("test-vrf")
        with pytest.raises(ValueError, match="already exists"):
            mgr.create("test-vrf")

    def test_delete_custom(self):
        mgr = VRFManager()
        mgr.create("temp-vrf")
        mgr.delete("temp-vrf")
        assert mgr.get("temp-vrf") is None

    def test_delete_nonexistent(self):
        mgr = VRFManager()
        with pytest.raises(KeyError, match="does not exist"):
            mgr.delete("no-such-vrf")

    def test_list_vrfs(self):
        mgr = VRFManager()
        names = mgr.list_vrfs()
        assert DEFAULT_VRF_NAME in names
        assert MGMT_VRF_NAME in names
        assert OOB_VRF_NAME in names


class TestVRFIsolation:
    def test_different_vrfs_isolated(self):
        mgr = VRFManager()
        assert mgr.is_isolated(MGMT_VRF_NAME, OOB_VRF_NAME)

    def test_same_vrf_not_isolated(self):
        mgr = VRFManager()
        assert not mgr.is_isolated(MGMT_VRF_NAME, MGMT_VRF_NAME)

    def test_nonexistent_vrf_isolated(self):
        mgr = VRFManager()
        assert mgr.is_isolated("nonexistent", MGMT_VRF_NAME)


class TestVRFRouting:
    def test_add_and_lookup(self):
        vrf = VRF(name="test")
        route = Route(destination_prefix="0.0.0.0", next_hop="10.0.0.1", interface="eth0")
        vrf.add_route(route)
        addr = IPv8Address.parse("0.0.0.0.10.1.2.3")
        result = vrf.lookup(addr)
        assert result is not None

    def test_separate_routing_tables(self):
        mgr = VRFManager()
        route = Route(destination_prefix="0.0.0.0", next_hop="10.0.0.1", interface="eth0")
        mgr.management.add_route(route)
        addr = IPv8Address.parse("0.0.0.0.10.1.2.3")
        # Route exists in management VRF
        assert mgr.management.lookup(addr) is not None
        # But not in OOB VRF
        assert mgr.oob.lookup(addr) is None

    def test_default_vrf_routing(self):
        mgr = VRFManager()
        route = Route(destination_prefix="0.0.0.0", next_hop="192.168.0.1", interface="eth0")
        mgr.default.add_route(route)
        addr = IPv8Address.parse("0.0.0.0.192.168.1.1")
        assert mgr.default.lookup(addr) is not None


# ---------------------------------------------------------------------------
# RN VRF naming convention (spec §3.2)
# ---------------------------------------------------------------------------

class TestIPv8VRFHelpers:
    def test_vrf_name_format(self):
        assert ipv8_vrf_name(64496) == "ipv8-asn-64496"
        assert ipv8_vrf_name(0) == "ipv8-asn-0"
        assert ipv8_vrf_name(4294967295) == "ipv8-asn-4294967295"

    def test_vrf_rd_format(self):
        assert ipv8_vrf_rd(64496) == "64496:65535"
        assert ipv8_vrf_rd(0) == "0:65535"


class TestBindRN:
    def test_bind_rn_creates_vrf(self):
        mgr = VRFManager()
        vrf = mgr.bind_rn(64496)
        assert vrf.name == "ipv8-asn-64496"
        assert vrf.route_distinguisher == "64496:65535"
        assert vrf.bound_rn == 64496

    def test_bind_rn_idempotent(self):
        mgr = VRFManager()
        v1 = mgr.bind_rn(64496)
        v2 = mgr.bind_rn(64496)
        assert v1 is v2

    def test_bind_rn_multiple(self):
        mgr = VRFManager()
        mgr.bind_rn(64496)
        mgr.bind_rn(64497)
        mgr.bind_rn(100)
        assert "ipv8-asn-64496" in mgr.list_vrfs()
        assert "ipv8-asn-64497" in mgr.list_vrfs()
        assert "ipv8-asn-100" in mgr.list_vrfs()

    def test_get_rn_vrf(self):
        mgr = VRFManager()
        mgr.bind_rn(64496)
        vrf = mgr.get_rn_vrf(64496)
        assert vrf is not None
        assert vrf.bound_rn == 64496

    def test_get_rn_vrf_not_bound_returns_none(self):
        mgr = VRFManager()
        assert mgr.get_rn_vrf(64496) is None

    def test_has_forwarding_context_true(self):
        mgr = VRFManager()
        mgr.bind_rn(64496)
        assert mgr.has_forwarding_context(64496)

    def test_has_forwarding_context_false_for_transit(self):
        mgr = VRFManager()
        # 64497 not bound — transit-only
        assert not mgr.has_forwarding_context(64497)

    def test_bound_rns_sorted(self):
        mgr = VRFManager()
        mgr.bind_rn(64498)
        mgr.bind_rn(64496)
        mgr.bind_rn(64497)
        assert mgr.bound_rns() == [64496, 64497, 64498]

    def test_bind_rn_custom_description(self):
        mgr = VRFManager()
        vrf = mgr.bind_rn(64496, description="corp uplink")
        assert vrf.description == "corp uplink"

    def test_bind_rn_default_description(self):
        mgr = VRFManager()
        vrf = mgr.bind_rn(64496)
        assert "64496" in vrf.description

    def test_rn_vrf_isolated_from_management(self):
        mgr = VRFManager()
        mgr.bind_rn(64496)
        assert mgr.is_isolated("ipv8-asn-64496", MGMT_VRF_NAME)

    def test_rn_vrf_has_routing_table(self):
        mgr = VRFManager()
        vrf = mgr.bind_rn(64496)
        route = Route(destination_prefix="0.0.0.0", next_hop="10.0.0.1", interface="eth0")
        vrf.add_route(route)
        addr = IPv8Address.parse("0-10.1.2.3")
        assert vrf.lookup(addr) is not None
