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
