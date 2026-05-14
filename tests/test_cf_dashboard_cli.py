# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for CF performance dashboard CLI."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from ipv8lab.cli import cf_dashboard_cli
from ipv8lab.cli.cf_dashboard_cli import app

runner = CliRunner()


def _reset() -> None:
    cf_dashboard_cli._state = None


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
        assert data["intrazone_cf"] == 0

    def test_init_with_cf(self) -> None:
        result = runner.invoke(app, ["init", "--intrazone-cf", "500", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["intrazone_cf"] == 500

    def test_init_resets(self) -> None:
        runner.invoke(app, ["add-path", "p1", "64497", "--rtt", "0.1"])
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["status", "--json"])
        data = json.loads(result.output)
        assert data["paths"] == 0


# ---------------------------------------------------------------------------
# add-path
# ---------------------------------------------------------------------------

class TestAddPath:
    def setup_method(self) -> None:
        _reset()

    def test_add_path(self) -> None:
        result = runner.invoke(app, ["add-path", "p1", "64497", "--rtt", "0.2"])
        assert result.exit_code == 0
        assert "p1" in result.output

    def test_add_path_json(self) -> None:
        result = runner.invoke(app, ["add-path", "p1", "64497", "--rtt", "0.1", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["path_id"] == "p1"
        assert data["origin_asn"] == 64497
        assert data["cf_value"] > 0

    def test_add_path_with_as_path(self) -> None:
        result = runner.invoke(app, ["add-path", "p1", "64497", "--as-path", "64498,64497", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["as_path"] == [64498, 64497]

    def test_add_path_with_hop_cfs(self) -> None:
        result = runner.invoke(app, ["add-path", "p1", "64497", "--hop-cfs", "100,200", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["hop_cfs"] == [100, 200]
        assert data["accumulated_cf"] == 300

    def test_add_path_with_distance(self) -> None:
        result = runner.invoke(app, [
            "add-path", "p1", "64497",
            "--distance-km", "500", "--measured-rtt-ms", "6.0", "--json",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["distance_km"] == 500.0

    def test_add_path_bad_cf(self) -> None:
        result = runner.invoke(app, ["add-path", "p1", "64497", "--rtt", "1.5"])
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# remove-path
# ---------------------------------------------------------------------------

class TestRemovePath:
    def setup_method(self) -> None:
        _reset()

    def test_remove(self) -> None:
        runner.invoke(app, ["add-path", "p1", "64497"])
        result = runner.invoke(app, ["remove-path", "p1", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["removed"] is True

    def test_remove_nonexistent(self) -> None:
        result = runner.invoke(app, ["remove-path", "nope", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["removed"] is False


# ---------------------------------------------------------------------------
# rank
# ---------------------------------------------------------------------------

class TestRank:
    def setup_method(self) -> None:
        _reset()

    def test_rank_empty(self) -> None:
        result = runner.invoke(app, ["rank"])
        assert result.exit_code == 0
        assert "No paths" in result.output

    def test_rank_json(self) -> None:
        runner.invoke(app, ["add-path", "high", "64497", "--rtt", "0.5"])
        runner.invoke(app, ["add-path", "low", "64498", "--rtt", "0.05"])
        result = runner.invoke(app, ["rank", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 2
        assert data[0]["path_id"] == "low"

    def test_rank_rich(self) -> None:
        runner.invoke(app, ["add-path", "p1", "64497", "--rtt", "0.1"])
        result = runner.invoke(app, ["rank"])
        assert result.exit_code == 0
        assert "p1" in result.output


# ---------------------------------------------------------------------------
# best
# ---------------------------------------------------------------------------

class TestBest:
    def setup_method(self) -> None:
        _reset()

    def test_best_empty(self) -> None:
        result = runner.invoke(app, ["best"])
        assert result.exit_code == 0
        assert "No paths" in result.output

    def test_best_json(self) -> None:
        runner.invoke(app, ["add-path", "high", "64497", "--rtt", "0.8"])
        runner.invoke(app, ["add-path", "low", "64498", "--rtt", "0.01"])
        result = runner.invoke(app, ["best", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["path_id"] == "low"

    def test_best_empty_json(self) -> None:
        result = runner.invoke(app, ["best", "--json"])
        assert result.exit_code == 0
        assert json.loads(result.output) is None


# ---------------------------------------------------------------------------
# anomalies
# ---------------------------------------------------------------------------

class TestAnomalies:
    def setup_method(self) -> None:
        _reset()

    def test_no_anomalies(self) -> None:
        result = runner.invoke(app, ["anomalies"])
        assert result.exit_code == 0
        assert "No anomalies" in result.output

    def test_no_anomalies_json(self) -> None:
        result = runner.invoke(app, ["anomalies", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data == []

    def test_anomaly_detected(self) -> None:
        runner.invoke(app, [
            "add-path", "fast", "64500",
            "--distance-km", "10000", "--measured-rtt-ms", "1",
        ])
        result = runner.invoke(app, ["anomalies", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 1
        assert data[0]["path_id"] == "fast"

    def test_anomaly_rich(self) -> None:
        runner.invoke(app, [
            "add-path", "fast", "64500",
            "--distance-km", "10000", "--measured-rtt-ms", "1",
        ])
        result = runner.invoke(app, ["anomalies"])
        assert result.exit_code == 0
        assert "fast" in result.output


# ---------------------------------------------------------------------------
# benchmarks
# ---------------------------------------------------------------------------

class TestBenchmarks:
    def setup_method(self) -> None:
        _reset()

    def test_benchmarks_json(self) -> None:
        result = runner.invoke(app, ["benchmarks", "-n", "10", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 6
        assert all("name" in b for b in data)

    def test_benchmarks_rich(self) -> None:
        result = runner.invoke(app, ["benchmarks", "-n", "10"])
        assert result.exit_code == 0
        assert "address_parse" in result.output


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
        assert data["paths"] == 0

    def test_status_after_ops(self) -> None:
        runner.invoke(app, ["add-path", "p1", "64497", "--rtt", "0.1"])
        result = runner.invoke(app, ["status", "--json"])
        data = json.loads(result.output)
        assert data["paths"] == 1
        assert data["best_path"] == "p1"

    def test_status_rich(self) -> None:
        result = runner.invoke(app, ["status"])
        assert result.exit_code == 0
        assert "Paths" in result.output


# ---------------------------------------------------------------------------
# demo
# ---------------------------------------------------------------------------

class TestDemo:
    def setup_method(self) -> None:
        _reset()

    def test_demo(self) -> None:
        result = runner.invoke(app, ["demo"])
        assert result.exit_code == 0
        assert "Demo" in result.output or "anomaly" in result.output.lower()

    def test_demo_json(self) -> None:
        result = runner.invoke(app, ["demo", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["summary"]["paths"] == 4
        assert data["summary"]["anomalies"] == 1
        assert len(data["paths"]) == 4

    def test_demo_resets_state(self) -> None:
        runner.invoke(app, ["add-path", "old", "99999"])
        runner.invoke(app, ["demo", "--json"])
        result = runner.invoke(app, ["status", "--json"])
        data = json.loads(result.output)
        assert data["paths"] == 4
