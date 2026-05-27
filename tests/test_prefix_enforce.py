# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for /16 Minimum Prefix Enforcement at eBGP8 boundaries per Section 19.7."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from ipv8lab.address import IPv8Address
from ipv8lab.prefix_enforce import (
    BGP8PrefixAd,
    FilterAction,
    PrefixEnforcer,
)
from ipv8lab.cli.prefix_enforce_cli import app

runner = CliRunner()


# ===================================================================
# BGP8PrefixAd
# ===================================================================

class TestBGP8PrefixAd:
    def test_cidr(self) -> None:
        ad = BGP8PrefixAd(prefix=IPv8Address.parse("64496-10.0.0.0"), prefix_length=16)
        assert ad.cidr == "0.0.251.240.10.0.0.0/16"

    def test_is_too_specific_true(self) -> None:
        ad = BGP8PrefixAd(prefix=IPv8Address.parse("64496-10.1.0.0"), prefix_length=24)
        assert ad.is_too_specific()

    def test_is_too_specific_false_16(self) -> None:
        ad = BGP8PrefixAd(prefix=IPv8Address.parse("64496-10.0.0.0"), prefix_length=16)
        assert not ad.is_too_specific()

    def test_is_too_specific_false_8(self) -> None:
        ad = BGP8PrefixAd(prefix=IPv8Address.parse("64496-10.0.0.0"), prefix_length=8)
        assert not ad.is_too_specific()

    def test_is_too_specific_17(self) -> None:
        ad = BGP8PrefixAd(prefix=IPv8Address.parse("64496-10.0.0.0"), prefix_length=17)
        assert ad.is_too_specific()


# ===================================================================
# PrefixEnforcer — filtering
# ===================================================================

class TestPrefixEnforcer:
    def test_accept_slash_16(self) -> None:
        e = PrefixEnforcer()
        ad = BGP8PrefixAd(prefix=IPv8Address.parse("64496-10.0.0.0"), prefix_length=16)
        result = e.filter_advertisement(ad)
        assert result.action == FilterAction.ACCEPT
        assert result.alert is None

    def test_accept_slash_8(self) -> None:
        e = PrefixEnforcer()
        ad = BGP8PrefixAd(prefix=IPv8Address.parse("64496-10.0.0.0"), prefix_length=8)
        result = e.filter_advertisement(ad)
        assert result.action == FilterAction.ACCEPT

    def test_reject_slash_24(self) -> None:
        e = PrefixEnforcer()
        ad = BGP8PrefixAd(prefix=IPv8Address.parse("64496-10.1.0.0"), prefix_length=24, peer_asn=64497)
        result = e.filter_advertisement(ad)
        assert result.action == FilterAction.REJECT
        assert result.alert is not None
        assert result.alert.severity == "SEC-ALERT"
        assert result.alert.prefix_length == 24

    def test_reject_slash_32(self) -> None:
        e = PrefixEnforcer()
        ad = BGP8PrefixAd(prefix=IPv8Address.parse("64496-10.1.2.3"), prefix_length=32)
        result = e.filter_advertisement(ad)
        assert result.action == FilterAction.REJECT

    def test_alert_recorded(self) -> None:
        e = PrefixEnforcer(router_id="br1")
        ad = BGP8PrefixAd(prefix=IPv8Address.parse("64496-10.1.0.0"), prefix_length=24, peer_asn=64497)
        e.filter_advertisement(ad, "wan0")
        assert len(e.alerts) == 1
        assert e.alerts[0].source == "br1"
        assert e.alerts[0].interface == "wan0"
        assert e.alerts[0].peer_asn == 64497

    def test_multiple_rejections(self) -> None:
        e = PrefixEnforcer()
        for i in range(5):
            ad = BGP8PrefixAd(prefix=IPv8Address.parse(f"64496.10.{i}.0.0"), prefix_length=24)
            e.filter_advertisement(ad)
        assert len(e.alerts) == 5

    def test_clear_alerts(self) -> None:
        e = PrefixEnforcer()
        ad = BGP8PrefixAd(prefix=IPv8Address.parse("64496-10.1.0.0"), prefix_length=24)
        e.filter_advertisement(ad)
        n = e.clear_alerts()
        assert n == 1
        assert len(e.alerts) == 0


# ===================================================================
# Batch
# ===================================================================

class TestBatch:
    def test_filter_batch(self) -> None:
        e = PrefixEnforcer()
        items = [
            (BGP8PrefixAd(prefix=IPv8Address.parse("64496-10.0.0.0"), prefix_length=16), "eth0"),
            (BGP8PrefixAd(prefix=IPv8Address.parse("64496-10.1.0.0"), prefix_length=24), "eth0"),
            (BGP8PrefixAd(prefix=IPv8Address.parse("64496-172.16.0.0"), prefix_length=12), "eth1"),
        ]
        results = e.filter_batch(items)
        assert results[0].action == FilterAction.ACCEPT
        assert results[1].action == FilterAction.REJECT
        assert results[2].action == FilterAction.ACCEPT


# ===================================================================
# Summary
# ===================================================================

class TestSummary:
    def test_summary_counters(self) -> None:
        e = PrefixEnforcer(router_id="r1")
        e.filter_advertisement(BGP8PrefixAd(prefix=IPv8Address.parse("64496-10.0.0.0"), prefix_length=16))
        e.filter_advertisement(BGP8PrefixAd(prefix=IPv8Address.parse("64496-10.1.0.0"), prefix_length=24))
        d = e.summary()
        assert d["router_id"] == "r1"
        assert d["min_prefix_length"] == 16
        assert d["accepted"] == 1
        assert d["rejected"] == 1
        assert d["alert_count"] == 1


# ===================================================================
# CLI tests
# ===================================================================

class TestPrefixEnforceCLI:
    def test_init_json(self) -> None:
        result = runner.invoke(app, ["init", "--router-id", "br1", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["router_id"] == "br1"
        assert data["min_prefix_length"] == 16

    def test_check_accept_json(self) -> None:
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["check", "64496-10.0.0.0", "16", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["action"] == "accept"

    def test_check_reject_json(self) -> None:
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["check", "64496-10.1.0.0", "24", "--peer-asn", "64497", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["action"] == "reject"
        assert data["alert"] is not None
        assert data["alert"]["severity"] == "SEC-ALERT"
        assert data["alert"]["prefix_length"] == 24

    def test_check_accept_slash_8_json(self) -> None:
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["check", "64496-10.0.0.0", "8", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["action"] == "accept"

    def test_alerts_json(self) -> None:
        runner.invoke(app, ["init"])
        runner.invoke(app, ["check", "64496-10.1.0.0", "24"])
        result = runner.invoke(app, ["alerts", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) >= 1

    def test_status_json(self) -> None:
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["status", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "accepted" in data
        assert "rejected" in data

    def test_no_args_help(self) -> None:
        result = runner.invoke(app, [])
        assert result.exit_code in (0, 2)
