# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for Address Usage Model per draft-thain-ipv8-02 Section 4.11."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from ipv8lab.address import IPv8Address
from ipv8lab.addr_usage import (
    ADDRESS_USAGE_TABLE,
    ExternalRouting,
    classify_address,
    usage_summary,
)
from ipv8lab.cli.addr_usage_cli import app

runner = CliRunner()


# ===================================================================
# Table structure
# ===================================================================

class TestTable:
    def test_table_has_10_entries(self) -> None:
        assert len(ADDRESS_USAGE_TABLE) == 10

    def test_all_entries_have_fields(self) -> None:
        for e in ADDRESS_USAGE_TABLE:
            assert e.prefix_pattern
            assert e.usage
            assert isinstance(e.external_routing, ExternalRouting)


# ===================================================================
# classify_address
# ===================================================================

class TestClassify:
    def test_internal_zone(self) -> None:
        addr = IPv8Address.parse("127.1.0.0.10.0.0.1")
        entry = classify_address(addr)
        assert entry.usage == "Internal devices (all zones)"
        assert entry.external_routing == ExternalRouting.NEVER

    def test_interop_dmz(self) -> None:
        addr = IPv8Address.parse("127.127.0.0.10.0.0.1")
        entry = classify_address(addr)
        assert entry.usage == "Inter-company interop DMZ"
        assert entry.external_routing == ExternalRouting.PRIVATE

    def test_rine_peering(self) -> None:
        addr = IPv8Address.parse("100.0.0.1.10.0.0.1")
        entry = classify_address(addr)
        assert entry.usage == "RINE peering links only"
        assert entry.external_routing == ExternalRouting.NEVER

    def test_interior_link(self) -> None:
        addr = IPv8Address.parse("0.0.251.240.222.0.0.1")
        entry = classify_address(addr)
        assert entry.usage == "Interior router links"
        assert entry.external_routing == ExternalRouting.NEVER

    def test_private_peering_asn(self) -> None:
        addr = IPv8Address.parse("0.0.255.254.10.0.0.1")
        entry = classify_address(addr)
        assert entry.usage == "Private BGP8 peering"
        assert entry.external_routing == ExternalRouting.PRIVATE

    def test_documentation_asn(self) -> None:
        addr = IPv8Address.parse("0.0.255.253.10.0.0.1")
        entry = classify_address(addr)
        assert entry.usage == "Documentation and testing"
        assert entry.external_routing == ExternalRouting.PRIVATE

    def test_ipv4_compatible(self) -> None:
        addr = IPv8Address.parse("0.0.0.0.8.8.8.8")
        entry = classify_address(addr)
        assert entry.usage == "IPv4 compatible (r.r.r.r = 0)"
        assert entry.external_routing == ExternalRouting.IPV4_ONLY

    def test_asn_unicast(self) -> None:
        addr = IPv8Address.parse("64496-192.0.2.1")
        entry = classify_address(addr)
        assert entry.usage == "Explicit public services only"
        assert entry.external_routing == ExternalRouting.GLOBAL

    def test_broadcast(self) -> None:
        addr = IPv8Address.parse("255.255.255.255.255.255.255.255")
        entry = classify_address(addr)
        assert entry.usage == "Broadcast"
        assert entry.external_routing == ExternalRouting.NEVER

    def test_cross_asn_multicast(self) -> None:
        addr = IPv8Address.parse("255.255.0.0.224.0.0.1")
        entry = classify_address(addr)
        assert entry.usage == "Cross-ASN multicast"
        assert entry.external_routing == ExternalRouting.GLOBAL


# ===================================================================
# usage_summary
# ===================================================================

class TestUsageSummary:
    def test_returns_dict(self) -> None:
        addr = IPv8Address.parse("64496-10.0.0.1")
        d = usage_summary(addr)
        assert d["address"] == "0.0.251.240.10.0.0.1"
        assert d["external_routing"] == "global"
        assert "pattern" in d
        assert "usage" in d
        assert "note" in d


# ===================================================================
# CLI tests
# ===================================================================

class TestAddrUsageCLI:
    def test_table_json(self) -> None:
        result = runner.invoke(app, ["table", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 10
        patterns = [e["pattern"] for e in data]
        assert "127.x.x.x.n.n.n.n" in patterns

    def test_table_text(self) -> None:
        result = runner.invoke(app, ["table"])
        assert result.exit_code == 0
        assert "127.x.x.x" in result.output
        assert "Pattern" in result.output

    def test_classify_json(self) -> None:
        result = runner.invoke(app, ["classify", "127.1.0.0.10.0.0.1", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["usage"] == "Internal devices (all zones)"
        assert data["external_routing"] == "never"

    def test_classify_text(self) -> None:
        result = runner.invoke(app, ["classify", "64496-192.0.2.1"])
        assert result.exit_code == 0
        assert "public" in result.output.lower()

    def test_classify_interop(self) -> None:
        result = runner.invoke(app, ["classify", "127.127.0.0.10.0.0.5", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["external_routing"] == "private"

    def test_batch_json(self) -> None:
        result = runner.invoke(app, [
            "batch",
            "127.1.0.0.10.0.0.1",
            "64496-192.0.2.1",
            "0.0.0.0.8.8.8.8",
            "--json",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 3
        routings = [d["external_routing"] for d in data]
        assert "never" in routings
        assert "global" in routings
        assert "ipv4-only" in routings

    def test_batch_text(self) -> None:
        result = runner.invoke(app, [
            "batch",
            "127.1.0.0.10.0.0.1",
            "64496-192.0.2.1",
        ])
        assert result.exit_code == 0
        assert "Internal" in result.output

    def test_no_args_help(self) -> None:
        result = runner.invoke(app, [])
        assert result.exit_code in (0, 2)
