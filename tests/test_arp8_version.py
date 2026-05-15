# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for ARP8-driven version selection per draft-thain-ipv8-02 Section 2."""

from __future__ import annotations

import json
import time

import pytest
from typer.testing import CliRunner

from ipv8lab.arp8_version import (
    ARP8VersionCache,
    ARP8VersionEntry,
    NeighborCapability,
    ProbeResult,
    RouterForwarder,
    TransmittedFrame,
    TRANSITION_PROPERTIES,
    VersionSelector,
    has_asn_attribution,
    _host_part,
    _asn_part,
)
from ipv8lab.cli.arp8_cli import app


runner = CliRunner()


# ===================================================================
# Helpers
# ===================================================================

class TestHelpers:
    def test_host_part_8_octets(self) -> None:
        assert _host_part("0.0.251.240.10.0.0.1") == "10.0.0.1"

    def test_host_part_5_parts(self) -> None:
        assert _host_part("64496.10.0.0.1") == "10.0.0.1"

    def test_host_part_4_parts(self) -> None:
        assert _host_part("10.0.0.1") == "10.0.0.1"

    def test_asn_part_8_octets(self) -> None:
        assert _asn_part("0.0.251.240.10.0.0.1") == "0.0.251.240"

    def test_asn_part_fallback(self) -> None:
        assert _asn_part("10.0.0.1") == "0.0.0.0"


# ===================================================================
# NeighborCapability enum
# ===================================================================

class TestNeighborCapability:
    def test_values(self) -> None:
        assert NeighborCapability.IPV8.value == "ipv8"
        assert NeighborCapability.IPV4_ONLY.value == "ipv4_only"
        assert NeighborCapability.UNKNOWN.value == "unknown"


# ===================================================================
# ARP8VersionEntry
# ===================================================================

class TestARP8VersionEntry:
    def test_not_expired(self) -> None:
        e = ARP8VersionEntry("1.2.3.4.10.0.0.1", "aa:bb:cc:dd:ee:ff", discovered_at=100.0)
        assert not e.is_expired(100.0)
        assert not e.is_expired(14499.0)

    def test_expired(self) -> None:
        e = ARP8VersionEntry("1.2.3.4.10.0.0.1", "aa:bb:cc:dd:ee:ff", discovered_at=100.0)
        assert e.is_expired(14500.0)

    def test_custom_ttl(self) -> None:
        e = ARP8VersionEntry("1.2.3.4.10.0.0.1", "aa:bb:cc:dd:ee:ff", discovered_at=0.0, ttl=60.0)
        assert not e.is_expired(59.0)
        assert e.is_expired(60.0)


# ===================================================================
# ARP8VersionCache — dual probe
# ===================================================================

class TestDualProbe:
    def test_discover_ipv8_neighbor(self) -> None:
        cache = ARP8VersionCache()
        outcome = cache.discover_neighbor("0.0.251.240.10.0.0.1", responds_arp8=True, mac_address="aa:bb:cc:dd:ee:01")
        assert outcome.probe_result == ProbeResult.ARP8_RESPONDED
        assert outcome.capability == NeighborCapability.IPV8
        assert outcome.mac_address == "aa:bb:cc:dd:ee:01"
        assert cache.size == 1

    def test_discover_ipv4_neighbor(self) -> None:
        cache = ARP8VersionCache()
        outcome = cache.discover_neighbor("0.0.251.240.10.0.0.2", responds_arp8=False, mac_address="aa:bb:cc:dd:ee:02")
        assert outcome.probe_result == ProbeResult.ARP4_RESPONDED
        assert outcome.capability == NeighborCapability.IPV4_ONLY

    def test_arp4_sent_50ms_after_arp8(self) -> None:
        cache = ARP8VersionCache()
        outcome = cache.discover_neighbor("0.0.251.240.10.0.0.3")
        assert outcome.arp4_sent_at == pytest.approx(outcome.arp8_sent_at + 0.050, abs=0.01)

    def test_discover_updates_cache(self) -> None:
        cache = ARP8VersionCache()
        cache.discover_neighbor("10.0.0.1", responds_arp8=True)
        assert cache.capability_of("10.0.0.1") == NeighborCapability.IPV8
        cache.discover_neighbor("10.0.0.1", responds_arp8=False)
        assert cache.capability_of("10.0.0.1") == NeighborCapability.IPV4_ONLY

    def test_discover_multiple(self) -> None:
        cache = ARP8VersionCache()
        cache.discover_neighbor("10.0.0.1", responds_arp8=True)
        cache.discover_neighbor("10.0.0.2", responds_arp8=False)
        assert cache.size == 2


# ===================================================================
# ARP8VersionCache — operations
# ===================================================================

class TestARP8VersionCache:
    def test_get_missing(self) -> None:
        cache = ARP8VersionCache()
        assert cache.get("no.such.addr") is None

    def test_capability_unknown_for_missing(self) -> None:
        cache = ARP8VersionCache()
        assert cache.capability_of("x") == NeighborCapability.UNKNOWN

    def test_learn_and_get(self) -> None:
        cache = ARP8VersionCache()
        e = ARP8VersionEntry("10.0.0.1", "aa:bb:cc:dd:ee:ff", capability=NeighborCapability.IPV8)
        cache.learn(e)
        assert cache.get("10.0.0.1") is e

    def test_flush(self) -> None:
        cache = ARP8VersionCache()
        cache.learn(ARP8VersionEntry("a", "m1"))
        cache.learn(ARP8VersionEntry("b", "m2"))
        assert cache.flush() == 2
        assert cache.size == 0

    def test_flush_expired(self) -> None:
        cache = ARP8VersionCache()
        old = ARP8VersionEntry("a", "m1", discovered_at=0.0, ttl=1.0)
        cache.learn(old)
        new = ARP8VersionEntry("b", "m2", discovered_at=time.time(), ttl=14400.0)
        cache.learn(new)
        removed = cache.flush_expired()
        assert removed == 1
        assert cache.size == 1

    def test_all_entries(self) -> None:
        cache = ARP8VersionCache()
        cache.learn(ARP8VersionEntry("a", "m1"))
        cache.learn(ARP8VersionEntry("b", "m2"))
        assert len(cache.all_entries()) == 2


# ===================================================================
# VersionSelector (Section 2.3)
# ===================================================================

class TestVersionSelector:
    def test_select_ipv8(self) -> None:
        frame = VersionSelector.select(
            "0.0.251.240.10.0.0.1",
            "0.0.251.241.10.0.0.2",
            NeighborCapability.IPV8,
        )
        assert frame.ip_version == 8
        assert frame.src == "0.0.251.240.10.0.0.1"
        assert frame.dst == "0.0.251.241.10.0.0.2"
        assert frame.downgraded is False

    def test_select_ipv4_only(self) -> None:
        frame = VersionSelector.select(
            "0.0.251.240.10.0.0.1",
            "0.0.251.241.10.0.0.2",
            NeighborCapability.IPV4_ONLY,
        )
        assert frame.ip_version == 4
        assert frame.src == "10.0.0.1"
        assert frame.dst == "10.0.0.2"
        assert frame.downgraded is True

    def test_select_unknown_defaults_to_downgrade(self) -> None:
        frame = VersionSelector.select("0.0.0.0.10.0.0.1", "0.0.0.0.10.0.0.2", NeighborCapability.UNKNOWN)
        assert frame.ip_version == 4
        assert frame.downgraded is True

    def test_ipv4_never_sees_version8(self) -> None:
        """Section 2.3: No IPv4 device ever receives a packet with version 8."""
        frame = VersionSelector.select("0.0.251.240.10.0.0.1", "0.0.0.0.192.168.1.1", NeighborCapability.IPV4_ONLY)
        assert frame.ip_version == 4


# ===================================================================
# Attribution (Section 2.5)
# ===================================================================

class TestAttribution:
    def test_ipv8_has_attribution(self) -> None:
        f = TransmittedFrame(ip_version=8, src="0.0.251.240.10.0.0.1", dst="0.0.251.241.10.0.0.2")
        assert has_asn_attribution(f) is True

    def test_ipv4_no_attribution(self) -> None:
        f = TransmittedFrame(ip_version=4, src="10.0.0.1", dst="10.0.0.2", downgraded=True)
        assert has_asn_attribution(f) is False


# ===================================================================
# RouterForwarder (Section 2.4)
# ===================================================================

class TestRouterForwarder:
    def test_add_interface(self) -> None:
        r = RouterForwarder()
        iface = r.add_interface("eth0")
        assert iface.name == "eth0"
        assert r.get_interface("eth0") is iface

    def test_interfaces_list(self) -> None:
        r = RouterForwarder()
        r.add_interface("eth0")
        r.add_interface("eth1")
        assert len(r.interfaces) == 2

    def test_forward_ipv8_neighbor(self) -> None:
        r = RouterForwarder()
        iface = r.add_interface("eth0")
        iface.cache.discover_neighbor("0.0.251.241.10.0.0.2", responds_arp8=True)
        decision = r.forward("0.0.251.240.10.0.0.1", "0.0.251.241.10.0.0.2", "eth0", "0.0.251.241.10.0.0.2")
        assert decision.frame.ip_version == 8
        assert decision.xlate8_needed is False
        assert decision.outgoing_interface == "eth0"

    def test_forward_ipv4_neighbor_downgrade(self) -> None:
        r = RouterForwarder()
        iface = r.add_interface("eth1")
        iface.cache.discover_neighbor("192.168.1.1", responds_arp8=False)
        decision = r.forward("0.0.251.240.10.0.0.1", "0.0.251.241.10.0.0.2", "eth1", "192.168.1.1")
        assert decision.frame.ip_version == 4
        assert decision.frame.downgraded is True
        assert decision.xlate8_needed is True

    def test_forward_unknown_interface_raises(self) -> None:
        r = RouterForwarder()
        with pytest.raises(ValueError, match="Unknown interface"):
            r.forward("a", "b", "nosuch", "c")

    def test_multi_interface_independent(self) -> None:
        """A single router MAY serve IPv8 and IPv4 on different interfaces."""
        r = RouterForwarder()
        eth0 = r.add_interface("eth0")
        eth1 = r.add_interface("eth1")
        eth0.cache.discover_neighbor("10.0.0.2", responds_arp8=True)
        eth1.cache.discover_neighbor("192.168.1.2", responds_arp8=False)

        d0 = r.forward("0.0.251.240.10.0.0.1", "0.0.251.241.10.0.0.2", "eth0", "10.0.0.2")
        d1 = r.forward("0.0.251.240.10.0.0.1", "0.0.251.241.10.0.0.3", "eth1", "192.168.1.2")
        assert d0.frame.ip_version == 8
        assert d1.frame.ip_version == 4


# ===================================================================
# TransitionProperties (Section 2.6)
# ===================================================================

class TestTransitionProperties:
    def test_six_properties(self) -> None:
        assert len(TRANSITION_PROPERTIES) == 6

    def test_ipv4_never_gets_v8(self) -> None:
        assert any("version 8" in p for p in TRANSITION_PROPERTIES)


# ===================================================================
# CLI tests
# ===================================================================

class TestARP8CLI:
    def test_discover_ipv8(self) -> None:
        result = runner.invoke(app, ["discover", "0.0.251.240.10.0.0.1", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["capability"] == "ipv8"
        assert data["probe_result"] == "arp8_responded"

    def test_discover_ipv4(self) -> None:
        result = runner.invoke(app, ["discover", "0.0.0.0.192.168.1.1", "--ipv4", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["capability"] == "ipv4_only"

    def test_discover_text(self) -> None:
        result = runner.invoke(app, ["discover", "0.0.251.240.10.0.0.1"])
        assert result.exit_code == 0
        assert "Capability:" in result.output

    def test_select_json(self) -> None:
        # First discover so cache has data
        runner.invoke(app, ["discover", "0.0.251.241.10.0.0.2"])
        result = runner.invoke(app, ["select", "0.0.251.240.10.0.0.1", "0.0.251.241.10.0.0.2", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["ip_version"] in (4, 8)

    def test_select_text(self) -> None:
        runner.invoke(app, ["discover", "0.0.251.241.10.0.0.3"])
        result = runner.invoke(app, ["select", "0.0.251.240.10.0.0.1", "0.0.251.241.10.0.0.3"])
        assert result.exit_code == 0
        assert "IP version:" in result.output

    def test_cache_empty(self) -> None:
        from ipv8lab.cli.arp8_cli import _cache
        _cache.flush()
        result = runner.invoke(app, ["cache"])
        assert result.exit_code == 0
        assert "empty" in result.output.lower()

    def test_cache_json(self) -> None:
        from ipv8lab.cli.arp8_cli import _cache
        _cache.flush()
        runner.invoke(app, ["discover", "10.0.0.99"])
        result = runner.invoke(app, ["cache", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) >= 1

    def test_cache_text(self) -> None:
        runner.invoke(app, ["discover", "10.0.0.100"])
        result = runner.invoke(app, ["cache"])
        assert result.exit_code == 0
        assert "10.0.0.100" in result.output

    def test_simulate_ipv8(self) -> None:
        result = runner.invoke(app, [
            "simulate", "0.0.251.240.10.0.0.1", "0.0.251.241.10.0.0.2",
            "--iface", "ge0", "--json",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["ip_version"] == 8
        assert data["xlate8_needed"] is False

    def test_simulate_ipv4_downgrade(self) -> None:
        result = runner.invoke(app, [
            "simulate", "0.0.251.240.10.0.0.1", "0.0.0.0.192.168.1.1",
            "--iface", "ge1", "--ipv4", "--json",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["ip_version"] == 4
        assert data["downgraded"] is True
        assert data["xlate8_needed"] is True

    def test_simulate_text(self) -> None:
        result = runner.invoke(app, [
            "simulate", "0.0.251.240.10.0.0.1", "0.0.251.241.10.0.0.2",
            "--iface", "ge2",
        ])
        assert result.exit_code == 0
        assert "Interface:" in result.output

    def test_status_json(self) -> None:
        result = runner.invoke(app, ["status", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "cache_size" in data
        assert "transition_properties" in data

    def test_status_text(self) -> None:
        result = runner.invoke(app, ["status"])
        assert result.exit_code == 0
        assert "Cache size:" in result.output

    def test_no_args_help(self) -> None:
        result = runner.invoke(app, [])
        assert result.exit_code in (0, 2)
