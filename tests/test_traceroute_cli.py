# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for Traceroute8 CLI commands."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from ipv8lab.cli.traceroute_cli import app

runner = CliRunner()


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------

class TestRunCmd:
    def test_run(self) -> None:
        result = runner.invoke(app, ["run", "64496-10.0.0.1", "64500-10.0.0.1"])
        assert result.exit_code == 0
        assert "traceroute8" in result.output.lower() or "✓" in result.output

    def test_run_json(self) -> None:
        result = runner.invoke(app, ["run", "64496-10.0.0.1", "64500-10.0.0.1", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["completed"] is True
        assert data["hop_count"] >= 1

    def test_run_custom_hops(self) -> None:
        result = runner.invoke(app, [
            "run", "64496-10.0.0.1", "64500-10.0.0.1", "-n", "3", "--json",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["completed"] is True

    def test_run_bad_addr(self) -> None:
        result = runner.invoke(app, ["run", "bad", "64500-10.0.0.1"])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# linear
# ---------------------------------------------------------------------------

class TestLinearCmd:
    def test_linear(self) -> None:
        result = runner.invoke(app, ["linear"])
        assert result.exit_code == 0
        assert "✓" in result.output

    def test_linear_json(self) -> None:
        result = runner.invoke(app, ["linear", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["completed"] is True

    def test_linear_custom_hops(self) -> None:
        result = runner.invoke(app, ["linear", "-n", "10", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["completed"] is True
        assert data["hop_count"] == 9


# ---------------------------------------------------------------------------
# diamond
# ---------------------------------------------------------------------------

class TestDiamondCmd:
    def test_diamond(self) -> None:
        result = runner.invoke(app, ["diamond"])
        assert result.exit_code == 0
        assert "✓" in result.output

    def test_diamond_json(self) -> None:
        result = runner.invoke(app, ["diamond", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["completed"] is True
        assert data["hop_count"] == 2


# ---------------------------------------------------------------------------
# loop
# ---------------------------------------------------------------------------

class TestLoopCmd:
    def test_loop(self) -> None:
        result = runner.invoke(app, ["loop"])
        assert result.exit_code == 0
        assert "loop" in result.output.lower() or "✗" in result.output

    def test_loop_json(self) -> None:
        result = runner.invoke(app, ["loop", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["completed"] is False
        assert "loop" in (data["error"] or "").lower()


# ---------------------------------------------------------------------------
# multipath
# ---------------------------------------------------------------------------

class TestMultipathCmd:
    def test_multipath(self) -> None:
        result = runner.invoke(app, ["multipath"])
        assert result.exit_code == 0
        assert "✓" in result.output

    def test_multipath_json(self) -> None:
        result = runner.invoke(app, ["multipath", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["completed"] is True


# ---------------------------------------------------------------------------
# demo
# ---------------------------------------------------------------------------

class TestDemoCmd:
    def test_demo(self) -> None:
        result = runner.invoke(app, ["demo"])
        assert result.exit_code == 0
        assert "Linear" in result.output
        assert "Diamond" in result.output
        assert "Loop" in result.output

    def test_demo_json(self) -> None:
        result = runner.invoke(app, ["demo", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data["scenarios"]) == 4
        # First three should complete, loop should not
        assert data["scenarios"][0]["completed"] is True
        assert data["scenarios"][2]["completed"] is False  # loop
