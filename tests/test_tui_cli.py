# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for TUI CLI commands."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from ipv8lab.cli.tui_cli import app

runner = CliRunner()


# ---------------------------------------------------------------------------
# demo
# ---------------------------------------------------------------------------


class TestDemo:
    def test_demo(self) -> None:
        result = runner.invoke(app, ["demo"])
        assert result.exit_code == 0
        assert "Demo Network" in result.output or "Summary" in result.output

    def test_demo_json(self) -> None:
        result = runner.invoke(app, ["demo", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "title" in data
        assert "summary" in data
        assert data["summary"]["nodes"] > 0

    def test_demo_has_flows(self) -> None:
        result = runner.invoke(app, ["demo", "--json"])
        data = json.loads(result.output)
        assert len(data["flows"]) > 0

    def test_demo_has_qos(self) -> None:
        result = runner.invoke(app, ["demo", "--json"])
        data = json.loads(result.output)
        assert len(data["qos_classes"]) > 0

    def test_demo_has_nat(self) -> None:
        result = runner.invoke(app, ["demo", "--json"])
        data = json.loads(result.output)
        assert len(data["nat_mappings"]) > 0


# ---------------------------------------------------------------------------
# panels
# ---------------------------------------------------------------------------


class TestPanels:
    def test_panels(self) -> None:
        result = runner.invoke(app, ["panels"])
        assert result.exit_code == 0
        assert "topology" in result.output

    def test_panels_json(self) -> None:
        result = runner.invoke(app, ["panels", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data["panels"]) == 6
        names = [p["id"] for p in data["panels"]]
        assert "topology" in names
        assert "routes" in names
        assert "flows" in names
        assert "qos" in names
        assert "nat" in names
        assert "docker" in names


# ---------------------------------------------------------------------------
# snapshot
# ---------------------------------------------------------------------------


class TestSnapshot:
    def test_snapshot(self) -> None:
        result = runner.invoke(app, ["snapshot"])
        assert result.exit_code == 0
        assert "Snapshot" in result.output

    def test_snapshot_json(self) -> None:
        result = runner.invoke(app, ["snapshot", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "title" in data
        assert "nodes" in data
        assert "routes" in data
        assert "flows" in data

    def test_snapshot_has_docker(self) -> None:
        result = runner.invoke(app, ["snapshot", "--json"])
        data = json.loads(result.output)
        assert len(data["docker_nodes"]) > 0
