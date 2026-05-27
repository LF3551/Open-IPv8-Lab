# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for Interior Link Convention Protection per Section 19.4."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from ipv8lab.address import IPv8Address
from ipv8lab.ilink_protection import (
    FilterAction,
    InteriorLinkFilter,
    is_interior_link_host,
)
from ipv8lab.cli.ilink_protection_cli import app

runner = CliRunner()


# ===================================================================
# is_interior_link_host
# ===================================================================

class TestIsInteriorLinkHost:
    def test_222_x(self) -> None:
        addr = IPv8Address.parse("64496-222.0.0.1")
        assert is_interior_link_host(addr)

    def test_non_222(self) -> None:
        addr = IPv8Address.parse("64496-10.0.0.1")
        assert not is_interior_link_host(addr)

    def test_222_255(self) -> None:
        addr = IPv8Address.parse("64496-222.255.255.255")
        assert is_interior_link_host(addr)


# ===================================================================
# BGP8 advertisement filtering
# ===================================================================

class TestBGP8Filtering:
    def test_non_222_accepted(self) -> None:
        f = InteriorLinkFilter()
        addr = IPv8Address.parse("64496-10.0.0.0")
        result = f.filter_bgp8_advertisement(addr)
        assert result.action == FilterAction.ACCEPT

    def test_222_dropped(self) -> None:
        f = InteriorLinkFilter()
        addr = IPv8Address.parse("64496-222.0.0.1")
        result = f.filter_bgp8_advertisement(addr)
        assert result.action == FilterAction.DROP
        assert result.trap is not None
        assert result.trap.severity == "E3"

    def test_trap_recorded(self) -> None:
        f = InteriorLinkFilter(router_id="r1")
        addr = IPv8Address.parse("64496-222.1.0.0")
        f.filter_bgp8_advertisement(addr, "eth0")
        assert len(f.traps) == 1
        assert f.traps[0].source == "r1"
        assert f.traps[0].interface == "eth0"

    def test_multiple_violations(self) -> None:
        f = InteriorLinkFilter()
        for i in range(3):
            f.filter_bgp8_advertisement(IPv8Address.parse(f"64496.222.0.0.{i}"))
        assert len(f.traps) == 3


# ===================================================================
# Packet filtering (egress)
# ===================================================================

class TestPacketFiltering:
    def test_non_222_accepted(self) -> None:
        f = InteriorLinkFilter()
        addr = IPv8Address.parse("64496-10.0.0.1")
        result = f.filter_packet(addr)
        assert result.action == FilterAction.ACCEPT

    def test_222_dropped(self) -> None:
        f = InteriorLinkFilter()
        addr = IPv8Address.parse("64496-222.0.0.1")
        result = f.filter_packet(addr, "wan0")
        assert result.action == FilterAction.DROP
        assert result.trap is not None

    def test_egress_trap_content(self) -> None:
        f = InteriorLinkFilter(router_id="br2")
        addr = IPv8Address.parse("64496-222.5.0.1")
        f.filter_packet(addr, "wan0")
        assert f.traps[0].violation == "Interior link address in egress packet"


# ===================================================================
# Batch + clear
# ===================================================================

class TestBatchAndClear:
    def test_filter_batch(self) -> None:
        f = InteriorLinkFilter()
        items = [
            (IPv8Address.parse("64496-10.0.0.1"), "eth0"),
            (IPv8Address.parse("64496-222.0.0.1"), "eth0"),
            (IPv8Address.parse("64496-222.1.0.0"), "eth1"),
        ]
        results = f.filter_batch(items)
        assert results[0].action == FilterAction.ACCEPT
        assert results[1].action == FilterAction.DROP
        assert results[2].action == FilterAction.DROP

    def test_clear_traps(self) -> None:
        f = InteriorLinkFilter()
        f.filter_bgp8_advertisement(IPv8Address.parse("64496-222.0.0.1"))
        n = f.clear_traps()
        assert n == 1
        assert len(f.traps) == 0

    def test_summary(self) -> None:
        f = InteriorLinkFilter(router_id="r3")
        d = f.summary()
        assert d["router_id"] == "r3"
        assert d["trap_count"] == 0


# ===================================================================
# CLI tests
# ===================================================================

class TestILinkProtectionCLI:
    def test_init_json(self) -> None:
        result = runner.invoke(app, ["init", "--router-id", "br1", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["router_id"] == "br1"

    def test_bgp8_accept_json(self) -> None:
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["bgp8", "64496-10.0.0.0", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["action"] == "accept"

    def test_bgp8_drop_json(self) -> None:
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["bgp8", "64496-222.0.0.1", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["action"] == "drop"
        assert data["trap"] is not None
        assert data["trap"]["severity"] == "E3"

    def test_packet_accept_json(self) -> None:
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["packet", "64496-10.0.0.1", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["action"] == "accept"

    def test_packet_drop_json(self) -> None:
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["packet", "64496-222.0.0.1", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["action"] == "drop"

    def test_traps_json(self) -> None:
        runner.invoke(app, ["init"])
        runner.invoke(app, ["bgp8", "64496-222.0.0.1"])
        result = runner.invoke(app, ["traps", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) >= 1

    def test_status_json(self) -> None:
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["status", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "trap_count" in data

    def test_no_args_help(self) -> None:
        result = runner.invoke(app, [])
        assert result.exit_code in (0, 2)
