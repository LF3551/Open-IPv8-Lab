# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for XLATE8 flow CLI."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from ipv8lab.cli import xlate8_cli
from ipv8lab.cli.xlate8_cli import app

runner = CliRunner()


def _reset() -> None:
    xlate8_cli._flow = None
    xlate8_cli._counter = 0.0


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------

class TestInit:
    def setup_method(self) -> None:
        _reset()

    def test_init_default(self) -> None:
        result = runner.invoke(app, ["init"])
        assert result.exit_code == 0
        assert "127.1.0.0" in result.output

    def test_init_custom(self) -> None:
        result = runner.invoke(app, ["init", "--zone-prefix", "127.2.0.0", "--external-asn", "64500"])
        assert result.exit_code == 0
        assert "127.2.0.0" in result.output

    def test_init_json(self) -> None:
        result = runner.invoke(app, ["init", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["status"] == "initialized"
        assert data["zone_prefix"] == "127.1.0.0"
        assert data["external_asn"] == 64496

    def test_init_resets(self) -> None:
        runner.invoke(app, ["dns-add", "x.iv8", "64497-10.0.1.1"])
        runner.invoke(app, ["init", "--json"])
        result = runner.invoke(app, ["status", "--json"])
        data = json.loads(result.output)
        assert data["dns_records"] == 0


# ---------------------------------------------------------------------------
# dns-add
# ---------------------------------------------------------------------------

class TestDnsAdd:
    def setup_method(self) -> None:
        _reset()

    def test_dns_add(self) -> None:
        result = runner.invoke(app, ["dns-add", "web.iv8", "64497-10.0.1.100"])
        assert result.exit_code == 0
        assert "web.iv8" in result.output

    def test_dns_add_json(self) -> None:
        result = runner.invoke(app, ["dns-add", "web.iv8", "64497-10.0.1.100", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["hostname"] == "web.iv8"
        assert data["dns_size"] == 1

    def test_dns_add_with_ttl(self) -> None:
        result = runner.invoke(app, ["dns-add", "web.iv8", "64497-10.0.1.100", "--ttl", "7200", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["ttl"] == 7200

    def test_dns_add_bad_address(self) -> None:
        result = runner.invoke(app, ["dns-add", "web.iv8", "invalid"])
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# dns-lookup
# ---------------------------------------------------------------------------

class TestDnsLookup:
    def setup_method(self) -> None:
        _reset()

    def test_lookup_found(self) -> None:
        runner.invoke(app, ["dns-add", "web.iv8", "64497-10.0.1.100"])
        result = runner.invoke(app, ["dns-lookup", "web.iv8", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["found"] is True
        assert data["hostname"] == "web.iv8"

    def test_lookup_not_found(self) -> None:
        result = runner.invoke(app, ["dns-lookup", "nope.iv8", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["found"] is False

    def test_lookup_rich_found(self) -> None:
        runner.invoke(app, ["dns-add", "web.iv8", "64497-10.0.1.100"])
        result = runner.invoke(app, ["dns-lookup", "web.iv8"])
        assert result.exit_code == 0
        assert "web.iv8" in result.output

    def test_lookup_rich_nxdomain(self) -> None:
        result = runner.invoke(app, ["dns-lookup", "nope.iv8"])
        assert result.exit_code == 0
        assert "NXDOMAIN" in result.output


# ---------------------------------------------------------------------------
# egress
# ---------------------------------------------------------------------------

class TestEgress:
    def setup_method(self) -> None:
        _reset()
        runner.invoke(app, ["dns-add", "web.iv8", "64497-10.0.1.100"])

    def test_egress_success(self) -> None:
        result = runner.invoke(app, ["egress", "web.iv8", "127.1.0.0.10.0.1.10", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["success"] is True
        assert data["hostname"] == "web.iv8"

    def test_egress_blocked(self) -> None:
        result = runner.invoke(app, ["egress", "unknown.iv8", "127.1.0.0.10.0.1.10", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["success"] is False

    def test_egress_rich(self) -> None:
        result = runner.invoke(app, ["egress", "web.iv8", "127.1.0.0.10.0.1.10"])
        assert result.exit_code == 0
        assert "Egress" in result.output

    def test_egress_bad_address(self) -> None:
        result = runner.invoke(app, ["egress", "web.iv8", "invalid"])
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# ingress
# ---------------------------------------------------------------------------

class TestIngress:
    def setup_method(self) -> None:
        _reset()
        runner.invoke(app, ["dns-add", "web.iv8", "64497-10.0.1.100"])
        runner.invoke(app, ["egress", "web.iv8", "127.1.0.0.10.0.1.10"])

    def test_ingress_success(self) -> None:
        # After egress, XLATE8 table has an entry. Get translated src.
        status = runner.invoke(app, ["table", "--json"])
        entries = json.loads(status.output)
        ext_addr = entries[0]["external"]

        result = runner.invoke(app, ["ingress", "64497-10.0.1.100", ext_addr, "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["success"] is True

    def test_ingress_blocked(self) -> None:
        result = runner.invoke(app, ["ingress", "64497-10.0.1.100", "64499-10.0.1.1", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["success"] is False

    def test_ingress_bad_address(self) -> None:
        result = runner.invoke(app, ["ingress", "invalid", "64497-10.0.1.100"])
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# round-trip
# ---------------------------------------------------------------------------

class TestRoundTrip:
    def setup_method(self) -> None:
        _reset()
        runner.invoke(app, ["dns-add", "web.iv8", "64497-10.0.1.100"])

    def test_round_trip_success(self) -> None:
        result = runner.invoke(app, ["round-trip", "web.iv8", "127.1.0.0.10.0.1.10", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["success"] is True
        assert data["egress"] is not None
        assert data["ingress"] is not None

    def test_round_trip_blocked(self) -> None:
        result = runner.invoke(app, ["round-trip", "unknown.iv8", "127.1.0.0.10.0.1.10", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["success"] is False

    def test_round_trip_rich(self) -> None:
        result = runner.invoke(app, ["round-trip", "web.iv8", "127.1.0.0.10.0.1.10"])
        assert result.exit_code == 0
        assert "Round-trip" in result.output

    def test_round_trip_bad_address(self) -> None:
        result = runner.invoke(app, ["round-trip", "web.iv8", "invalid"])
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# table
# ---------------------------------------------------------------------------

class TestTable:
    def setup_method(self) -> None:
        _reset()

    def test_table_empty(self) -> None:
        result = runner.invoke(app, ["table"])
        assert result.exit_code == 0
        assert "empty" in result.output.lower()

    def test_table_empty_json(self) -> None:
        result = runner.invoke(app, ["table", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data == []

    def test_table_after_egress(self) -> None:
        runner.invoke(app, ["dns-add", "web.iv8", "64497-10.0.1.100"])
        runner.invoke(app, ["egress", "web.iv8", "127.1.0.0.10.0.1.10"])
        result = runner.invoke(app, ["table", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 1
        assert data[0]["dns_validated"] is True


# ---------------------------------------------------------------------------
# events
# ---------------------------------------------------------------------------

class TestEvents:
    def setup_method(self) -> None:
        _reset()

    def test_events_empty(self) -> None:
        result = runner.invoke(app, ["events"])
        assert result.exit_code == 0
        assert "No events" in result.output

    def test_events_empty_json(self) -> None:
        result = runner.invoke(app, ["events", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data == []

    def test_events_after_egress(self) -> None:
        runner.invoke(app, ["dns-add", "web.iv8", "64497-10.0.1.100"])
        runner.invoke(app, ["egress", "web.iv8", "127.1.0.0.10.0.1.10"])
        result = runner.invoke(app, ["events", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) >= 2

    def test_events_filter_direction(self) -> None:
        runner.invoke(app, ["dns-add", "web.iv8", "64497-10.0.1.100"])
        runner.invoke(app, ["round-trip", "web.iv8", "127.1.0.0.10.0.1.10"])
        result = runner.invoke(app, ["events", "--direction", "ingress", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert all(e["direction"] == "ingress" for e in data)

    def test_events_rich(self) -> None:
        runner.invoke(app, ["dns-add", "web.iv8", "64497-10.0.1.100"])
        runner.invoke(app, ["egress", "web.iv8", "127.1.0.0.10.0.1.10"])
        result = runner.invoke(app, ["events"])
        assert result.exit_code == 0
        assert "egress" in result.output


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

class TestStatus:
    def setup_method(self) -> None:
        _reset()

    def test_status_empty(self) -> None:
        result = runner.invoke(app, ["status", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["dns_records"] == 0
        assert data["xlate_entries"] == 0

    def test_status_after_ops(self) -> None:
        runner.invoke(app, ["dns-add", "web.iv8", "64497-10.0.1.100"])
        runner.invoke(app, ["egress", "web.iv8", "127.1.0.0.10.0.1.10"])
        result = runner.invoke(app, ["status", "--json"])
        data = json.loads(result.output)
        assert data["dns_records"] == 1
        assert data["xlate_entries"] == 1
        assert data["events"] >= 3

    def test_status_rich(self) -> None:
        result = runner.invoke(app, ["status"])
        assert result.exit_code == 0
        assert "Zone prefix" in result.output


# ---------------------------------------------------------------------------
# demo
# ---------------------------------------------------------------------------

class TestDemo:
    def setup_method(self) -> None:
        _reset()

    def test_demo(self) -> None:
        result = runner.invoke(app, ["demo"])
        assert result.exit_code == 0
        assert "Demo" in result.output or "passed" in result.output.lower()

    def test_demo_json(self) -> None:
        result = runner.invoke(app, ["demo", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data["trips"]) == 3
        assert data["trips"][0]["success"] is True
        assert data["trips"][1]["success"] is True
        assert data["trips"][2]["success"] is False  # unknown.iv8

    def test_demo_resets_state(self) -> None:
        runner.invoke(app, ["dns-add", "old.iv8", "64500-10.0.1.1"])
        runner.invoke(app, ["demo", "--json"])
        result = runner.invoke(app, ["status", "--json"])
        data = json.loads(result.output)
        assert data["dns_records"] == 2  # only demo records
