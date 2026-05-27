# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for RINE Prefix Protection per Section 19.3."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from ipv8lab.address import IPv8Address
from ipv8lab.rine_protection import (
    FilterAction,
    InterfaceType,
    RINEPrefixFilter,
    is_rine_prefix,
)
from ipv8lab.cli.rine_protection_cli import app

runner = CliRunner()


# ===================================================================
# is_rine_prefix
# ===================================================================

class TestIsRinePrefix:
    def test_100_x(self) -> None:
        assert is_rine_prefix(IPv8Address.parse("100.0.0.1.10.0.0.1"))

    def test_non_rine(self) -> None:
        assert not is_rine_prefix(IPv8Address.parse("64496-10.0.0.1"))

    def test_100_255(self) -> None:
        assert is_rine_prefix(IPv8Address.parse("100.255.255.255.1.2.3.4"))


# ===================================================================
# RINEPrefixFilter — packet filtering
# ===================================================================

class TestPacketFiltering:
    def test_non_rine_always_accepted(self) -> None:
        f = RINEPrefixFilter()
        addr = IPv8Address.parse("64496-10.0.0.1")
        result = f.filter_packet(addr, "eth0", InterfaceType.EXTERNAL)
        assert result.action == FilterAction.ACCEPT

    def test_rine_on_peering_accepted(self) -> None:
        f = RINEPrefixFilter()
        addr = IPv8Address.parse("100.0.0.1.10.0.0.1")
        result = f.filter_packet(addr, "ixp0", InterfaceType.PEERING)
        assert result.action == FilterAction.ACCEPT

    def test_rine_on_external_dropped(self) -> None:
        f = RINEPrefixFilter()
        addr = IPv8Address.parse("100.0.0.1.10.0.0.1")
        result = f.filter_packet(addr, "eth0", InterfaceType.EXTERNAL)
        assert result.action == FilterAction.DROP
        assert result.alert is not None
        assert result.alert.severity == "SEC-ALERT"

    def test_rine_on_internal_dropped(self) -> None:
        f = RINEPrefixFilter()
        addr = IPv8Address.parse("100.1.2.3.10.0.0.1")
        result = f.filter_packet(addr, "vlan100", InterfaceType.INTERNAL)
        assert result.action == FilterAction.DROP

    def test_alert_recorded(self) -> None:
        f = RINEPrefixFilter(router_id="r1")
        addr = IPv8Address.parse("100.0.0.1.10.0.0.1")
        f.filter_packet(addr, "eth0", InterfaceType.EXTERNAL)
        assert len(f.alerts) == 1
        assert f.alerts[0].source == "r1"

    def test_multiple_alerts(self) -> None:
        f = RINEPrefixFilter()
        for i in range(3):
            f.filter_packet(
                IPv8Address.parse(f"100.0.0.{i}.10.0.0.1"),
                "eth0",
                InterfaceType.EXTERNAL,
            )
        assert len(f.alerts) == 3


# ===================================================================
# BGP8 advertisement filtering
# ===================================================================

class TestBGP8Filtering:
    def test_non_rine_advertisement_accepted(self) -> None:
        f = RINEPrefixFilter()
        addr = IPv8Address.parse("64496-0.0.0.0")
        result = f.filter_bgp8_advertisement(addr, "eth0")
        assert result.action == FilterAction.ACCEPT

    def test_rine_advertisement_dropped(self) -> None:
        f = RINEPrefixFilter()
        addr = IPv8Address.parse("100.0.0.1.0.0.0.0")
        result = f.filter_bgp8_advertisement(addr, "eth0")
        assert result.action == FilterAction.DROP
        assert result.alert is not None
        assert "eBGP8" in result.reason

    def test_bgp8_alert_recorded(self) -> None:
        f = RINEPrefixFilter()
        f.filter_bgp8_advertisement(IPv8Address.parse("100.0.0.1.0.0.0.0"), "eth0")
        assert len(f.alerts) == 1
        assert f.alerts[0].interface_type == "ebgp8"


# ===================================================================
# Batch + clear
# ===================================================================

class TestBatchAndClear:
    def test_filter_batch(self) -> None:
        f = RINEPrefixFilter()
        items = [
            (IPv8Address.parse("64496-10.0.0.1"), "eth0", InterfaceType.EXTERNAL),
            (IPv8Address.parse("100.0.0.1.10.0.0.1"), "eth0", InterfaceType.EXTERNAL),
            (IPv8Address.parse("100.0.0.2.10.0.0.1"), "ixp0", InterfaceType.PEERING),
        ]
        results = f.filter_batch(items)
        assert results[0].action == FilterAction.ACCEPT
        assert results[1].action == FilterAction.DROP
        assert results[2].action == FilterAction.ACCEPT

    def test_clear_alerts(self) -> None:
        f = RINEPrefixFilter()
        f.filter_packet(IPv8Address.parse("100.0.0.1.10.0.0.1"), "eth0", InterfaceType.EXTERNAL)
        n = f.clear_alerts()
        assert n == 1
        assert len(f.alerts) == 0

    def test_summary(self) -> None:
        f = RINEPrefixFilter(router_id="r2")
        d = f.summary()
        assert d["router_id"] == "r2"
        assert d["alert_count"] == 0


# ===================================================================
# CLI tests
# ===================================================================

class TestRINEProtectionCLI:
    def test_init_json(self) -> None:
        result = runner.invoke(app, ["init", "--router-id", "br1", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["router_id"] == "br1"

    def test_check_accept_json(self) -> None:
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["check", "64496-10.0.0.1", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["action"] == "accept"

    def test_check_drop_json(self) -> None:
        runner.invoke(app, ["init"])
        result = runner.invoke(app, [
            "check", "100.0.0.1.10.0.0.1",
            "--iface-type", "external", "--json",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["action"] == "drop"
        assert data["alert"] is not None

    def test_check_peering_accept_json(self) -> None:
        runner.invoke(app, ["init"])
        result = runner.invoke(app, [
            "check", "100.0.0.1.10.0.0.1",
            "--iface-type", "peering", "--json",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["action"] == "accept"

    def test_bgp8_drop_json(self) -> None:
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["bgp8", "100.0.0.1.0.0.0.0", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["action"] == "drop"

    def test_alerts_json(self) -> None:
        runner.invoke(app, ["init"])
        runner.invoke(app, ["check", "100.0.0.1.10.0.0.1", "--iface-type", "external"])
        result = runner.invoke(app, ["alerts", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) >= 1

    def test_status_json(self) -> None:
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["status", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "alert_count" in data

    def test_no_args_help(self) -> None:
        result = runner.invoke(app, [])
        assert result.exit_code in (0, 2)
