# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for multi-zone CLI commands."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from ipv8lab.cli import multizone_cli
from ipv8lab.cli.multizone_cli import app

runner = CliRunner()


def _reset() -> None:
    """Reset module-level state between tests."""
    multizone_cli._sim = None


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------

class TestInit:
    def setup_method(self) -> None:
        _reset()

    def test_init_default(self) -> None:
        result = runner.invoke(app, ["init"])
        assert result.exit_code == 0
        assert "initialized" in result.output.lower()

    def test_init_json(self) -> None:
        result = runner.invoke(app, ["init", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["status"] == "initialized"
        assert data["zones"] == 0
        assert data["links"] == 0

    def test_init_resets(self) -> None:
        runner.invoke(app, ["add-zone", "z1", "1"])
        runner.invoke(app, ["init", "--json"])
        result = runner.invoke(app, ["list-zones", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 0


# ---------------------------------------------------------------------------
# add-zone
# ---------------------------------------------------------------------------

class TestAddZone:
    def setup_method(self) -> None:
        _reset()

    def test_add_zone(self) -> None:
        result = runner.invoke(app, ["add-zone", "americas", "1"])
        assert result.exit_code == 0
        assert "americas" in result.output

    def test_add_zone_json(self) -> None:
        result = runner.invoke(app, ["add-zone", "europe", "2", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["name"] == "europe"
        assert data["zone_prefix"] == "127.2.0.0"
        assert data["total_zones"] == 1

    def test_add_duplicate(self) -> None:
        runner.invoke(app, ["add-zone", "dup", "1"])
        result = runner.invoke(app, ["add-zone", "dup", "2"])
        assert result.exit_code == 1

    def test_add_multiple(self) -> None:
        runner.invoke(app, ["add-zone", "z1", "1", "--json"])
        result = runner.invoke(app, ["add-zone", "z2", "2", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["total_zones"] == 2


# ---------------------------------------------------------------------------
# list-zones
# ---------------------------------------------------------------------------

class TestListZones:
    def setup_method(self) -> None:
        _reset()

    def test_list_empty(self) -> None:
        result = runner.invoke(app, ["list-zones"])
        assert result.exit_code == 0
        assert "No zones" in result.output

    def test_list_empty_json(self) -> None:
        result = runner.invoke(app, ["list-zones", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data == []

    def test_list_after_add(self) -> None:
        runner.invoke(app, ["add-zone", "z1", "1"])
        runner.invoke(app, ["add-zone", "z2", "2"])
        result = runner.invoke(app, ["list-zones", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 2
        names = {z["name"] for z in data}
        assert names == {"z1", "z2"}

    def test_list_rich(self) -> None:
        runner.invoke(app, ["add-zone", "z1", "1"])
        result = runner.invoke(app, ["list-zones"])
        assert result.exit_code == 0
        assert "z1" in result.output


# ---------------------------------------------------------------------------
# connect
# ---------------------------------------------------------------------------

class TestConnect:
    def setup_method(self) -> None:
        _reset()

    def test_connect(self) -> None:
        runner.invoke(app, ["add-zone", "a", "1"])
        runner.invoke(app, ["add-zone", "b", "2"])
        result = runner.invoke(app, ["connect", "a", "b"])
        assert result.exit_code == 0
        assert "a" in result.output and "b" in result.output

    def test_connect_json(self) -> None:
        runner.invoke(app, ["add-zone", "a", "1"])
        runner.invoke(app, ["add-zone", "b", "2"])
        result = runner.invoke(app, ["connect", "a", "b", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["link_a_b"]["source"] == "a"
        assert data["link_b_a"]["source"] == "b"
        assert data["total_links"] == 2

    def test_connect_unknown_zone(self) -> None:
        runner.invoke(app, ["add-zone", "a", "1"])
        result = runner.invoke(app, ["connect", "a", "nope"])
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# provision
# ---------------------------------------------------------------------------

class TestProvision:
    def setup_method(self) -> None:
        _reset()
        runner.invoke(app, ["add-zone", "z1", "1"])

    def test_provision(self) -> None:
        result = runner.invoke(app, ["provision", "z1", "dev-1"])
        assert result.exit_code == 0
        assert "dev-1" in result.output

    def test_provision_json(self) -> None:
        result = runner.invoke(app, ["provision", "z1", "dev-1", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["success"] is True
        assert data["client_id"] == "dev-1"
        assert data["zone"] == "z1"

    def test_provision_bad_zone(self) -> None:
        result = runner.invoke(app, ["provision", "nope", "dev-1"])
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# authenticate
# ---------------------------------------------------------------------------

class TestAuthenticate:
    def setup_method(self) -> None:
        _reset()
        runner.invoke(app, ["add-zone", "z1", "1"])

    def test_authenticate(self) -> None:
        result = runner.invoke(app, ["authenticate", "z1", "dev-1"])
        assert result.exit_code == 0
        assert "authenticated" in result.output.lower() or "✓" in result.output

    def test_authenticate_json(self) -> None:
        result = runner.invoke(app, ["authenticate", "z1", "dev-1", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["authenticated"] is True
        assert data["zone"] == "z1"

    def test_authenticate_bad_zone(self) -> None:
        result = runner.invoke(app, ["authenticate", "nope", "dev-1"])
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# route
# ---------------------------------------------------------------------------

class TestRoute:
    def setup_method(self) -> None:
        _reset()
        runner.invoke(app, ["add-zone", "a", "1"])
        runner.invoke(app, ["add-zone", "b", "2"])
        runner.invoke(app, ["connect", "a", "b"])
        runner.invoke(app, ["provision", "a", "dev-a"])
        runner.invoke(app, ["provision", "b", "dev-b"])

    def test_route(self) -> None:
        result = runner.invoke(app, ["route", "a", "b", "dev-a", "dev-b"])
        assert result.exit_code == 0
        assert "routed" in result.output.lower() or "✓" in result.output

    def test_route_json(self) -> None:
        result = runner.invoke(app, ["route", "a", "b", "dev-a", "dev-b", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["routed"] is True
        assert data["src_zone"] == "a"
        assert data["dst_zone"] == "b"

    def test_route_no_lease(self) -> None:
        result = runner.invoke(app, ["route", "a", "b", "dev-a", "nonexist"])
        assert result.exit_code == 1

    def test_route_bad_zone(self) -> None:
        result = runner.invoke(app, ["route", "nope", "b", "dev-a", "dev-b"])
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# acl-check
# ---------------------------------------------------------------------------

class TestAclCheck:
    def setup_method(self) -> None:
        _reset()
        runner.invoke(app, ["add-zone", "z1", "1"])

    def test_acl_check_permit(self) -> None:
        result = runner.invoke(app, ["acl-check", "z1", "device", "gateway"])
        assert result.exit_code == 0
        assert "PERMIT" in result.output

    def test_acl_check_json(self) -> None:
        result = runner.invoke(app, ["acl-check", "z1", "device", "gateway", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["permitted"] is True

    def test_acl_check_bad_zone(self) -> None:
        result = runner.invoke(app, ["acl-check", "nope", "a", "b"])
        assert result.exit_code == 1


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

    def test_events_after_actions(self) -> None:
        runner.invoke(app, ["add-zone", "z1", "1"])
        runner.invoke(app, ["provision", "z1", "d1"])
        result = runner.invoke(app, ["events", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) >= 2

    def test_events_filter_zone(self) -> None:
        runner.invoke(app, ["add-zone", "z1", "1"])
        runner.invoke(app, ["add-zone", "z2", "2"])
        result = runner.invoke(app, ["events", "--zone", "z1", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert all(e["zone"] == "z1" for e in data)

    def test_events_rich(self) -> None:
        runner.invoke(app, ["add-zone", "z1", "1"])
        result = runner.invoke(app, ["events"])
        assert result.exit_code == 0
        assert "z1" in result.output


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
        assert data["zones"] == 0

    def test_status_after_add(self) -> None:
        runner.invoke(app, ["add-zone", "z1", "1"])
        runner.invoke(app, ["add-zone", "z2", "2"])
        runner.invoke(app, ["connect", "z1", "z2"])
        result = runner.invoke(app, ["status", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["zones"] == 2
        assert data["links"] == 2
        assert data["all_passed"] is True

    def test_status_rich(self) -> None:
        result = runner.invoke(app, ["status"])
        assert result.exit_code == 0
        assert "Zones" in result.output


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
        assert data["zones"] == ["americas", "europe", "apac"]
        assert data["all_passed"] is True
        assert data["links"] == 6  # 3 connections * 2 bidirectional

    def test_demo_resets_state(self) -> None:
        runner.invoke(app, ["add-zone", "old", "99"])
        runner.invoke(app, ["demo", "--json"])
        result = runner.invoke(app, ["list-zones", "--json"])
        data = json.loads(result.output)
        names = {z["name"] for z in data}
        assert names == {"americas", "europe", "apac"}
