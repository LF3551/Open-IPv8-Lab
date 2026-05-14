# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for fuzzer CLI commands."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from ipv8lab.cli.fuzzer_cli import _reset, app

runner = CliRunner()


@pytest.fixture(autouse=True)
def _reset_state() -> None:
    _reset()


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------


class TestRun:
    def test_run_default(self) -> None:
        result = runner.invoke(app, ["run", "--count", "20", "--seed", "42"])
        assert result.exit_code == 0
        assert "Fuzzer Results" in result.output

    def test_run_json(self) -> None:
        result = runner.invoke(app, ["run", "--count", "10", "--seed", "42", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["total_cases"] == 10
        assert "crashes" in data
        assert "success_rate" in data

    def test_run_strategy(self) -> None:
        result = runner.invoke(app, ["run", "--count", "10", "--strategy", "bit_flip", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["total_cases"] == 10

    def test_run_bad_strategy(self) -> None:
        result = runner.invoke(app, ["run", "--strategy", "invalid"])
        assert result.exit_code != 0 or "Error" in result.output

    def test_run_bad_target(self) -> None:
        result = runner.invoke(app, ["run", "--target", "invalid"])
        assert result.exit_code != 0 or "Error" in result.output

    def test_run_all_strategies(self) -> None:
        for strat in ["bit_flip", "byte_random", "boundary", "truncate", "extend", "checksum", "field_mutate", "fragment", "combined"]:
            result = runner.invoke(app, ["run", "--count", "5", "--strategy", strat, "--seed", "42", "--json"])
            assert result.exit_code == 0


# ---------------------------------------------------------------------------
# generate
# ---------------------------------------------------------------------------


class TestGenerate:
    def test_generate(self) -> None:
        result = runner.invoke(app, ["generate", "--count", "5", "--seed", "42"])
        assert result.exit_code == 0
        assert "Generated" in result.output

    def test_generate_json(self) -> None:
        result = runner.invoke(app, ["generate", "--count", "3", "--seed", "42", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["count"] == 3
        assert len(data["cases"]) == 3

    def test_generate_has_hex(self) -> None:
        result = runner.invoke(app, ["generate", "--count", "1", "--seed", "42", "--json"])
        data = json.loads(result.output)
        case = data["cases"][0]
        assert "raw_hex" in case
        assert len(case["raw_hex"]) > 0


# ---------------------------------------------------------------------------
# strategies
# ---------------------------------------------------------------------------


class TestStrategies:
    def test_list(self) -> None:
        result = runner.invoke(app, ["strategies"])
        assert result.exit_code == 0
        assert "bit_flip" in result.output

    def test_json(self) -> None:
        result = runner.invoke(app, ["strategies", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data["strategies"]) == 9


# ---------------------------------------------------------------------------
# targets
# ---------------------------------------------------------------------------


class TestTargets:
    def test_list(self) -> None:
        result = runner.invoke(app, ["targets"])
        assert result.exit_code == 0
        assert "parser" in result.output

    def test_json(self) -> None:
        result = runner.invoke(app, ["targets", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data["targets"]) == 5


# ---------------------------------------------------------------------------
# demo
# ---------------------------------------------------------------------------


class TestDemo:
    def test_demo(self) -> None:
        result = runner.invoke(app, ["demo"])
        assert result.exit_code == 0
        assert "demo complete" in result.output

    def test_demo_json(self) -> None:
        result = runner.invoke(app, ["demo", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "demo_results" in data
        assert len(data["demo_results"]) >= 8  # 8 individual + 1 combined
