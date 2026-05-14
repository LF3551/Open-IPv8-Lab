# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for multi-zone simulation with Zone Server pairs."""

from __future__ import annotations

import pytest

from ipv8lab.address import IPv8Address
from ipv8lab.multizone import (
    InterZoneLink,
    MultiZoneEvent,
    MultiZoneSimulation,
    ZoneDefinition,
    ZoneInstance,
)


class _FakeClock:
    def __init__(self, now: float = 1_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


# ---------------------------------------------------------------------------
# ZoneDefinition
# ---------------------------------------------------------------------------

class TestZoneDefinition:
    def test_zone_prefix(self) -> None:
        d = ZoneDefinition(name="americas", zone_octet=1)
        assert d.zone_prefix == "127.1.0.0"

    def test_zone_prefix_tuple(self) -> None:
        d = ZoneDefinition(name="europe", zone_octet=2)
        assert d.zone_prefix_tuple == (127, 2, 0, 0)

    def test_custom_network_prefix(self) -> None:
        d = ZoneDefinition(name="apac", zone_octet=3, network_prefix=(192, 168, 1))
        assert d.network_prefix == (192, 168, 1)

    def test_defaults(self) -> None:
        d = ZoneDefinition(name="test", zone_octet=5)
        assert d.oauth8_key_id == "zone-key"
        assert d.lease_duration == 3600


# ---------------------------------------------------------------------------
# Zone creation
# ---------------------------------------------------------------------------

class TestZoneCreation:
    def test_add_single_zone(self) -> None:
        sim = MultiZoneSimulation()
        inst = sim.add_zone(ZoneDefinition(name="americas", zone_octet=1))
        assert isinstance(inst, ZoneInstance)
        assert sim.zone_count == 1
        assert inst.name == "americas"
        assert inst.zone_prefix == "127.1.0.0"

    def test_add_multiple_zones(self) -> None:
        sim = MultiZoneSimulation()
        sim.add_zone(ZoneDefinition(name="americas", zone_octet=1))
        sim.add_zone(ZoneDefinition(name="europe", zone_octet=2))
        sim.add_zone(ZoneDefinition(name="apac", zone_octet=3))
        assert sim.zone_count == 3
        assert sim.list_zones() == ["americas", "europe", "apac"]

    def test_duplicate_zone_raises(self) -> None:
        sim = MultiZoneSimulation()
        sim.add_zone(ZoneDefinition(name="americas", zone_octet=1))
        with pytest.raises(ValueError, match="already exists"):
            sim.add_zone(ZoneDefinition(name="americas", zone_octet=1))

    def test_zone_has_servers(self) -> None:
        sim = MultiZoneSimulation()
        inst = sim.add_zone(ZoneDefinition(name="z1", zone_octet=1))
        assert inst.primary is not None
        assert inst.secondary is not None

    def test_zone_created_event(self) -> None:
        sim = MultiZoneSimulation()
        sim.add_zone(ZoneDefinition(name="z1", zone_octet=1))
        evts = sim.events
        assert len(evts) == 1
        assert evts[0].event == "zone_created"
        assert evts[0].success is True

    def test_get_zone(self) -> None:
        sim = MultiZoneSimulation()
        sim.add_zone(ZoneDefinition(name="z1", zone_octet=1))
        z = sim.get_zone("z1")
        assert z.name == "z1"

    def test_get_zone_missing(self) -> None:
        sim = MultiZoneSimulation()
        with pytest.raises(KeyError, match="not found"):
            sim.get_zone("nope")


# ---------------------------------------------------------------------------
# Inter-zone links
# ---------------------------------------------------------------------------

class TestInterZoneLinks:
    def setup_method(self) -> None:
        self.sim = MultiZoneSimulation()
        self.sim.add_zone(ZoneDefinition(name="americas", zone_octet=1))
        self.sim.add_zone(ZoneDefinition(name="europe", zone_octet=2))
        self.sim.add_zone(ZoneDefinition(name="apac", zone_octet=3))

    def test_connect_zones(self) -> None:
        link_ab, link_ba = self.sim.connect_zones("americas", "europe")
        assert isinstance(link_ab, InterZoneLink)
        assert link_ab.source_zone == "americas"
        assert link_ab.target_zone == "europe"
        assert link_ba.source_zone == "europe"
        assert link_ba.target_zone == "americas"

    def test_link_count(self) -> None:
        self.sim.connect_zones("americas", "europe")
        self.sim.connect_zones("europe", "apac")
        assert self.sim.link_count == 4  # 2 links * 2 directions

    def test_connect_missing_zone(self) -> None:
        with pytest.raises(KeyError, match="not found"):
            self.sim.connect_zones("americas", "nowhere")

    def test_connect_missing_source(self) -> None:
        with pytest.raises(KeyError, match="not found"):
            self.sim.connect_zones("nowhere", "americas")

    def test_link_interface(self) -> None:
        link_ab, _ = self.sim.connect_zones("americas", "europe")
        assert "ibgp8" in link_ab.interface

    def test_link_event(self) -> None:
        self.sim.connect_zones("americas", "europe")
        link_events = [e for e in self.sim.events if e.event == "inter_zone_link"]
        assert len(link_events) == 1
        assert link_events[0].success is True


# ---------------------------------------------------------------------------
# Device provisioning
# ---------------------------------------------------------------------------

class TestMultiZoneProvisioning:
    def setup_method(self) -> None:
        self.clock = _FakeClock()
        self.sim = MultiZoneSimulation(clock=self.clock)
        self.sim.add_zone(ZoneDefinition(name="americas", zone_octet=1))
        self.sim.add_zone(ZoneDefinition(name="europe", zone_octet=2))

    def test_provision_device(self) -> None:
        lease = self.sim.provision_device("americas", "dev-01")
        assert lease is not None
        assert str(lease.address).startswith("127.1.0.0")

    def test_provision_in_different_zones(self) -> None:
        lease_a = self.sim.provision_device("americas", "dev-01")
        lease_e = self.sim.provision_device("europe", "dev-02")
        assert lease_a is not None
        assert lease_e is not None
        assert str(lease_a.address).startswith("127.1.0.0")
        assert str(lease_e.address).startswith("127.2.0.0")

    def test_provision_missing_zone(self) -> None:
        with pytest.raises(KeyError, match="not found"):
            self.sim.provision_device("nope", "dev-01")

    def test_provision_event(self) -> None:
        self.sim.provision_device("americas", "dev-01")
        prov_events = [e for e in self.sim.events if e.event == "provision"]
        assert len(prov_events) == 1
        assert prov_events[0].success is True


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

class TestMultiZoneAuth:
    def setup_method(self) -> None:
        self.clock = _FakeClock()
        self.sim = MultiZoneSimulation(clock=self.clock)
        self.sim.add_zone(ZoneDefinition(name="americas", zone_octet=1))

    def test_authenticate_device(self) -> None:
        result = self.sim.authenticate_device("americas", "dev-01", now=self.clock.now)
        assert result is True

    def test_authenticate_event(self) -> None:
        self.sim.authenticate_device("americas", "dev-01", now=self.clock.now)
        auth_events = [e for e in self.sim.events if e.event == "authenticate"]
        assert len(auth_events) == 1
        assert auth_events[0].success is True

    def test_authenticate_missing_zone(self) -> None:
        with pytest.raises(KeyError, match="not found"):
            self.sim.authenticate_device("nope", "dev-01")


# ---------------------------------------------------------------------------
# Inter-zone routing
# ---------------------------------------------------------------------------

class TestInterZoneRouting:
    def setup_method(self) -> None:
        self.clock = _FakeClock()
        self.sim = MultiZoneSimulation(clock=self.clock)
        self.sim.add_zone(ZoneDefinition(name="americas", zone_octet=1))
        self.sim.add_zone(ZoneDefinition(name="europe", zone_octet=2))
        self.sim.connect_zones("americas", "europe")

    def test_route_between_zones(self) -> None:
        self.sim.provision_device("americas", "dev-a")
        self.sim.provision_device("europe", "dev-e")
        src = self.sim.get_zone("americas").dhcp_server.get_lease("dev-a")
        dst = self.sim.get_zone("europe").dhcp_server.get_lease("dev-e")
        assert src is not None and dst is not None
        result = self.sim.route_between_zones("americas", "europe", src.address, dst.address)
        assert result is True

    def test_route_no_link(self) -> None:
        sim = MultiZoneSimulation(clock=self.clock)
        sim.add_zone(ZoneDefinition(name="a", zone_octet=1))
        sim.add_zone(ZoneDefinition(name="b", zone_octet=2))
        sim.provision_device("a", "dev-a")
        sim.provision_device("b", "dev-b")
        src = sim.get_zone("a").dhcp_server.get_lease("dev-a")
        dst = sim.get_zone("b").dhcp_server.get_lease("dev-b")
        assert src is not None and dst is not None
        result = sim.route_between_zones("a", "b", src.address, dst.address)
        assert result is False

    def test_route_event(self) -> None:
        self.sim.provision_device("americas", "dev-a")
        self.sim.provision_device("europe", "dev-e")
        src = self.sim.get_zone("americas").dhcp_server.get_lease("dev-a")
        dst = self.sim.get_zone("europe").dhcp_server.get_lease("dev-e")
        assert src is not None and dst is not None
        self.sim.route_between_zones("americas", "europe", src.address, dst.address)
        route_events = [e for e in self.sim.events if e.event == "inter_zone_route"]
        assert len(route_events) == 1

    def test_route_missing_zone(self) -> None:
        src = IPv8Address.parse("127.1.0.0.10.0.1.10")
        dst = IPv8Address.parse("127.2.0.0.10.0.1.10")
        with pytest.raises(KeyError, match="not found"):
            self.sim.route_between_zones("nope", "europe", src, dst)


# ---------------------------------------------------------------------------
# ACL8 cross-zone
# ---------------------------------------------------------------------------

class TestCrossZoneACL:
    def setup_method(self) -> None:
        self.sim = MultiZoneSimulation()
        self.sim.add_zone(ZoneDefinition(name="americas", zone_octet=1))

    def test_authorize_gateway(self) -> None:
        result = self.sim.authorize_cross_zone("americas", "dev-01", "gateway")
        assert result is True

    def test_deny_lateral(self) -> None:
        result = self.sim.authorize_cross_zone("americas", "dev-01", "other-device")
        assert result is False

    def test_acl_event(self) -> None:
        self.sim.authorize_cross_zone("americas", "dev-01", "gateway")
        acl_events = [e for e in self.sim.events if e.event == "acl8_cross_zone"]
        assert len(acl_events) == 1
        assert acl_events[0].success is True

    def test_authorize_missing_zone(self) -> None:
        with pytest.raises(KeyError, match="not found"):
            self.sim.authorize_cross_zone("nope", "dev", "gw")


# ---------------------------------------------------------------------------
# Full multi-zone scenario
# ---------------------------------------------------------------------------

class TestFullMultiZone:
    def setup_method(self) -> None:
        self.clock = _FakeClock()
        self.sim = MultiZoneSimulation(clock=self.clock)

    def test_three_zone_mesh(self) -> None:
        """Americas, Europe, APAC — full mesh, provision & route."""
        self.sim.add_zone(ZoneDefinition(name="americas", zone_octet=1))
        self.sim.add_zone(ZoneDefinition(name="europe", zone_octet=2))
        self.sim.add_zone(ZoneDefinition(name="apac", zone_octet=3))

        self.sim.connect_zones("americas", "europe")
        self.sim.connect_zones("europe", "apac")
        self.sim.connect_zones("americas", "apac")

        # Provision one device per zone
        self.sim.provision_device("americas", "dev-am")
        self.sim.provision_device("europe", "dev-eu")
        self.sim.provision_device("apac", "dev-ap")

        # Authenticate
        self.sim.authenticate_device("americas", "dev-am", now=self.clock.now)
        self.sim.authenticate_device("europe", "dev-eu", now=self.clock.now)
        self.sim.authenticate_device("apac", "dev-ap", now=self.clock.now)

        # Route americas → europe
        la = self.sim.get_zone("americas").dhcp_server.get_lease("dev-am")
        le = self.sim.get_zone("europe").dhcp_server.get_lease("dev-eu")
        assert la is not None and le is not None
        assert self.sim.route_between_zones("americas", "europe", la.address, le.address)

        # Route europe → apac
        lap = self.sim.get_zone("apac").dhcp_server.get_lease("dev-ap")
        assert lap is not None
        assert self.sim.route_between_zones("europe", "apac", le.address, lap.address)

        # Route americas → apac (direct)
        assert self.sim.route_between_zones("americas", "apac", la.address, lap.address)

        assert self.sim.all_events_passed
        assert len(self.sim.failed_events) == 0

    def test_isolated_zone_blocks_traffic(self) -> None:
        """Zone without link → routing fails."""
        self.sim.add_zone(ZoneDefinition(name="americas", zone_octet=1))
        self.sim.add_zone(ZoneDefinition(name="isolated", zone_octet=9))
        # No connect_zones — isolated

        self.sim.provision_device("americas", "dev-am")
        self.sim.provision_device("isolated", "dev-iso")

        la = self.sim.get_zone("americas").dhcp_server.get_lease("dev-am")
        li = self.sim.get_zone("isolated").dhcp_server.get_lease("dev-iso")
        assert la is not None and li is not None

        result = self.sim.route_between_zones("americas", "isolated", la.address, li.address)
        assert result is False
        assert not self.sim.all_events_passed

    def test_intra_zone_routing(self) -> None:
        """Routing within same zone uses local route."""
        self.sim.add_zone(ZoneDefinition(name="z1", zone_octet=1))
        self.sim.provision_device("z1", "dev-a")
        self.sim.provision_device("z1", "dev-b")
        la = self.sim.get_zone("z1").dhcp_server.get_lease("dev-a")
        lb = self.sim.get_zone("z1").dhcp_server.get_lease("dev-b")
        assert la is not None and lb is not None
        result = self.sim.route_between_zones("z1", "z1", la.address, lb.address)
        assert result is True

    def test_event_tracking(self) -> None:
        self.sim.add_zone(ZoneDefinition(name="z1", zone_octet=1))
        self.sim.add_zone(ZoneDefinition(name="z2", zone_octet=2))
        self.sim.connect_zones("z1", "z2")
        self.sim.provision_device("z1", "dev-1")
        self.sim.authenticate_device("z1", "dev-1", now=self.clock.now)

        event_types = {e.event for e in self.sim.events}
        assert "zone_created" in event_types
        assert "inter_zone_link" in event_types
        assert "provision" in event_types
        assert "authenticate" in event_types

    def test_acl_lateral_denied_across_zones(self) -> None:
        self.sim.add_zone(ZoneDefinition(name="z1", zone_octet=1))
        # lateral: device → other-device should be denied
        assert not self.sim.authorize_cross_zone("z1", "dev", "other-device")
        # gateway: device → gateway should be allowed
        assert self.sim.authorize_cross_zone("z1", "dev", "gateway")


# ---------------------------------------------------------------------------
# MultiZoneEvent
# ---------------------------------------------------------------------------

class TestMultiZoneEvent:
    def test_frozen(self) -> None:
        evt = MultiZoneEvent(zone="z1", event="test", success=True, detail="ok")
        assert evt.zone == "z1"
        assert evt.success is True

    def test_default_detail(self) -> None:
        evt = MultiZoneEvent(zone="z1", event="test", success=False)
        assert evt.detail == ""
