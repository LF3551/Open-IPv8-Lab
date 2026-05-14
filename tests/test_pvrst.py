# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for PVRST per Section 17.4."""

import pytest

from ipv8lab.pvrst import (
    DEFAULT_PRIORITY,
    PRIMARY_HOST_OCTET,
    ROOT_PRIORITY,
    SECONDARY_HOST_OCTET,
    PVRSTBridge,
    PVRSTConfig,
    ZoneServerRole,
    elect_root,
    make_primary_zone_server,
    make_secondary_zone_server,
)


class TestConstants:
    def test_primary_octet(self):
        assert PRIMARY_HOST_OCTET == 254

    def test_secondary_octet(self):
        assert SECONDARY_HOST_OCTET == 253

    def test_root_priority(self):
        assert ROOT_PRIORITY == 4096

    def test_default_priority(self):
        assert DEFAULT_PRIORITY == 32768


class TestPVRSTConfig:
    def test_primary_root_for_even(self):
        cfg = PVRSTConfig(priority=ROOT_PRIORITY, zone_server_role=ZoneServerRole.PRIMARY)
        assert cfg.is_root_for_vlan(2)
        assert cfg.is_root_for_vlan(100)
        assert cfg.is_root_for_vlan(4090)

    def test_primary_not_root_for_odd(self):
        cfg = PVRSTConfig(priority=ROOT_PRIORITY, zone_server_role=ZoneServerRole.PRIMARY)
        assert not cfg.is_root_for_vlan(1)
        assert not cfg.is_root_for_vlan(99)
        assert not cfg.is_root_for_vlan(4091)

    def test_secondary_root_for_odd(self):
        cfg = PVRSTConfig(priority=ROOT_PRIORITY, zone_server_role=ZoneServerRole.SECONDARY)
        assert cfg.is_root_for_vlan(1)
        assert cfg.is_root_for_vlan(99)
        assert cfg.is_root_for_vlan(4091)

    def test_secondary_not_root_for_even(self):
        cfg = PVRSTConfig(priority=ROOT_PRIORITY, zone_server_role=ZoneServerRole.SECONDARY)
        assert not cfg.is_root_for_vlan(2)
        assert not cfg.is_root_for_vlan(4090)

    def test_non_zone_server_never_root(self):
        cfg = PVRSTConfig(priority=ROOT_PRIORITY)
        assert not cfg.is_root_for_vlan(2)
        assert not cfg.is_root_for_vlan(1)

    def test_wrong_priority_not_root(self):
        cfg = PVRSTConfig(priority=DEFAULT_PRIORITY, zone_server_role=ZoneServerRole.PRIMARY)
        assert not cfg.is_root_for_vlan(2)

    def test_root_vlans_primary(self):
        cfg = PVRSTConfig(priority=ROOT_PRIORITY, zone_server_role=ZoneServerRole.PRIMARY)
        vlans = cfg.root_vlans(range(1, 11))
        assert vlans == [2, 4, 6, 8, 10]

    def test_root_vlans_secondary(self):
        cfg = PVRSTConfig(priority=ROOT_PRIORITY, zone_server_role=ZoneServerRole.SECONDARY)
        vlans = cfg.root_vlans(range(1, 11))
        assert vlans == [1, 3, 5, 7, 9]


class TestPVRSTBridge:
    def test_default_port_state_blocking(self):
        br = PVRSTBridge(bridge_id="br0")
        assert br.get_port_state(1, 1) == "blocking"

    def test_set_forwarding(self):
        br = PVRSTBridge(bridge_id="br0")
        br.set_port_state(1, 1, "forwarding")
        assert br.get_port_state(1, 1) == "forwarding"

    def test_invalid_state(self):
        br = PVRSTBridge(bridge_id="br0")
        with pytest.raises(ValueError, match="Invalid port state"):
            br.set_port_state(1, 1, "invalid")

    def test_per_vlan_isolation(self):
        br = PVRSTBridge(bridge_id="br0")
        br.set_port_state(1, 1, "forwarding")
        br.set_port_state(2, 1, "blocking")
        assert br.get_port_state(1, 1) == "forwarding"
        assert br.get_port_state(2, 1) == "blocking"


class TestFactoryFunctions:
    def test_make_primary(self):
        br = make_primary_zone_server("zs-primary")
        assert br.config.zone_server_role == ZoneServerRole.PRIMARY
        assert br.config.priority == ROOT_PRIORITY
        assert br.config.is_root_for_vlan(4090)

    def test_make_secondary(self):
        br = make_secondary_zone_server("zs-secondary")
        assert br.config.zone_server_role == ZoneServerRole.SECONDARY
        assert br.config.priority == ROOT_PRIORITY
        assert br.config.is_root_for_vlan(4091)


class TestElectRoot:
    def test_primary_wins_even_vlan(self):
        pri = make_primary_zone_server("zs1")
        sec = make_secondary_zone_server("zs2")
        assert elect_root([pri, sec], 100) is pri

    def test_secondary_wins_odd_vlan(self):
        pri = make_primary_zone_server("zs1")
        sec = make_secondary_zone_server("zs2")
        assert elect_root([pri, sec], 101) is sec

    def test_lowest_priority_fallback(self):
        b1 = PVRSTBridge("b1", PVRSTConfig(priority=8192))
        b2 = PVRSTBridge("b2", PVRSTConfig(priority=16384))
        assert elect_root([b2, b1], 1) is b1

    def test_empty_list(self):
        assert elect_root([], 1) is None
