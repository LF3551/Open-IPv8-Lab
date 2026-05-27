# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for NAT8 CLI commands."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from ipv8lab.cli.nat8_cli import _reset, app

runner = CliRunner()


def setup_function() -> None:
    _reset()


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------

class TestInit:
    def test_init_static(self) -> None:
        _reset()
        result = runner.invoke(app, ["init", "--mode", "static"])
        assert result.exit_code == 0
        assert "static" in result.output.lower()

    def test_init_dynamic(self) -> None:
        _reset()
        result = runner.invoke(app, ["init", "--mode", "dynamic"])
        assert result.exit_code == 0

    def test_init_pat(self) -> None:
        _reset()
        result = runner.invoke(app, ["init", "--mode", "pat", "--pat-addr", "64496-10.0.1.50"])
        assert result.exit_code == 0

    def test_init_json(self) -> None:
        _reset()
        result = runner.invoke(app, ["init", "--mode", "static", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["mode"] == "static"

    def test_init_bad_mode(self) -> None:
        _reset()
        result = runner.invoke(app, ["init", "--mode", "bad"])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# add-static
# ---------------------------------------------------------------------------

class TestAddStatic:
    def test_add_static(self) -> None:
        _reset()
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["add-static", "127.1.0.0.10.0.1.10", "64496-10.0.1.100"])
        assert result.exit_code == 0

    def test_add_static_json(self) -> None:
        _reset()
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["add-static", "127.1.0.0.10.0.1.10", "64496-10.0.1.100", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["mode"] == "static"

    def test_add_static_no_init(self) -> None:
        _reset()
        result = runner.invoke(app, ["add-static", "127.1.0.0.10.0.1.10", "64496-10.0.1.100"])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# add-pool
# ---------------------------------------------------------------------------

class TestAddPool:
    def test_add_pool(self) -> None:
        _reset()
        runner.invoke(app, ["init", "--mode", "dynamic"])
        result = runner.invoke(app, ["add-pool", "64496-10.0.1.200"])
        assert result.exit_code == 0

    def test_add_pool_json(self) -> None:
        _reset()
        runner.invoke(app, ["init", "--mode", "dynamic"])
        result = runner.invoke(app, ["add-pool", "64496-10.0.1.200", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["pool_size"] == 1


# ---------------------------------------------------------------------------
# translate
# ---------------------------------------------------------------------------

class TestTranslate:
    def test_egress(self) -> None:
        _reset()
        runner.invoke(app, ["init"])
        runner.invoke(app, ["add-static", "127.1.0.0.10.0.1.10", "64496-10.0.1.100"])
        result = runner.invoke(app, [
            "translate", "--src", "127.1.0.0.10.0.1.10", "--dst", "64497-10.0.1.1",
        ])
        assert result.exit_code == 0
        assert "✓" in result.output

    def test_egress_json(self) -> None:
        _reset()
        runner.invoke(app, ["init"])
        runner.invoke(app, ["add-static", "127.1.0.0.10.0.1.10", "64496-10.0.1.100"])
        result = runner.invoke(app, [
            "translate", "--src", "127.1.0.0.10.0.1.10", "--dst", "64497-10.0.1.1", "--json",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["translated"] is True

    def test_ingress(self) -> None:
        _reset()
        runner.invoke(app, ["init"])
        runner.invoke(app, ["add-static", "127.1.0.0.10.0.1.10", "64496-10.0.1.100"])
        result = runner.invoke(app, [
            "translate", "--src", "64497-10.0.1.1", "--dst", "64496-10.0.1.100",
            "--dir", "ingress",
        ])
        assert result.exit_code == 0

    def test_no_mapping(self) -> None:
        _reset()
        runner.invoke(app, ["init"])
        result = runner.invoke(app, [
            "translate", "--src", "127.1.0.0.10.0.1.10", "--dst", "64497-10.0.1.1", "--json",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["translated"] is False


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

class TestStatus:
    def test_status(self) -> None:
        _reset()
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["status"])
        assert result.exit_code == 0
        assert "NAT8" in result.output

    def test_status_json(self) -> None:
        _reset()
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["status", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["mode"] == "static"


# ---------------------------------------------------------------------------
# mappings
# ---------------------------------------------------------------------------

class TestMappings:
    def test_mappings_empty(self) -> None:
        _reset()
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["mappings"])
        assert result.exit_code == 0
        assert "No active" in result.output

    def test_mappings_json(self) -> None:
        _reset()
        runner.invoke(app, ["init"])
        runner.invoke(app, ["add-static", "127.1.0.0.10.0.1.10", "64496-10.0.1.100"])
        result = runner.invoke(app, ["mappings", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 1


# ---------------------------------------------------------------------------
# release
# ---------------------------------------------------------------------------

class TestRelease:
    def test_release(self) -> None:
        _reset()
        runner.invoke(app, ["init"])
        runner.invoke(app, ["add-static", "127.1.0.0.10.0.1.10", "64496-10.0.1.100"])
        result = runner.invoke(app, ["release", "127.1.0.0.10.0.1.10"])
        assert result.exit_code == 0
        assert "✓" in result.output

    def test_release_json(self) -> None:
        _reset()
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["release", "127.1.0.0.10.0.1.99", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["released"] is False


# ---------------------------------------------------------------------------
# demo
# ---------------------------------------------------------------------------

class TestDemo:
    def test_demo(self) -> None:
        _reset()
        result = runner.invoke(app, ["demo"])
        assert result.exit_code == 0
        assert "STATIC" in result.output
        assert "DYNAMIC" in result.output
        assert "PAT" in result.output

    def test_demo_json(self) -> None:
        _reset()
        result = runner.invoke(app, ["demo", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data["scenarios"]) == 3
