# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for NetFlow8 CLI commands."""

from __future__ import annotations

import json
import os
import tempfile

from typer.testing import CliRunner

from ipv8lab.cli.netflow8_cli import _reset, app

runner = CliRunner()


def setup_function() -> None:
    _reset()


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------


class TestInit:
    def test_init(self) -> None:
        _reset()
        result = runner.invoke(app, ["init"])
        assert result.exit_code == 0
        assert "initialized" in result.output.lower()

    def test_init_json(self) -> None:
        _reset()
        result = runner.invoke(app, ["init", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["status"] == "initialized"

    def test_init_custom_timeouts(self) -> None:
        _reset()
        result = runner.invoke(app, [
            "init", "--active-timeout", "60", "--idle-timeout", "5", "--json",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["active_timeout"] == 60.0
        assert data["idle_timeout"] == 5.0


# ---------------------------------------------------------------------------
# observe
# ---------------------------------------------------------------------------


class TestObserve:
    def test_observe(self) -> None:
        _reset()
        runner.invoke(app, ["init"])
        result = runner.invoke(app, [
            "observe", "--src", "64496-10.0.1.10", "--dst", "64497-10.0.1.1",
        ])
        assert result.exit_code == 0
        assert "1 packet" in result.output

    def test_observe_multiple(self) -> None:
        _reset()
        runner.invoke(app, ["init"])
        result = runner.invoke(app, [
            "observe", "--src", "64496-10.0.1.10", "--dst", "64497-10.0.1.1",
            "--count", "5",
        ])
        assert result.exit_code == 0
        assert "5 packet" in result.output

    def test_observe_json(self) -> None:
        _reset()
        runner.invoke(app, ["init"])
        result = runner.invoke(app, [
            "observe", "--src", "64496-10.0.1.10", "--dst", "64497-10.0.1.1",
            "--sport", "80", "--dport", "443", "--json",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["observed"] == 1
        assert data["active_flows"] == 1

    def test_observe_no_init(self) -> None:
        _reset()
        result = runner.invoke(app, [
            "observe", "--src", "64496-10.0.1.10", "--dst", "64497-10.0.1.1",
        ])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------


class TestExport:
    def test_export_all_json(self) -> None:
        _reset()
        runner.invoke(app, ["init"])
        runner.invoke(app, [
            "observe", "--src", "64496-10.0.1.10", "--dst", "64497-10.0.1.1",
        ])
        result = runner.invoke(app, ["export", "--all", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 1
        assert data[0]["packets"] == 1

    def test_export_empty(self) -> None:
        _reset()
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["export"])
        assert result.exit_code == 0
        assert "No flows" in result.output

    def test_export_to_file(self) -> None:
        _reset()
        runner.invoke(app, ["init"])
        runner.invoke(app, [
            "observe", "--src", "64496-10.0.1.10", "--dst", "64497-10.0.1.1",
        ])
        with tempfile.NamedTemporaryFile(suffix=".nf8", delete=False) as f:
            path = f.name
        try:
            result = runner.invoke(app, ["export", "--all", "--output", path])
            assert result.exit_code == 0
            assert os.path.getsize(path) > 0
        finally:
            os.unlink(path)

    def test_export_to_file_json(self) -> None:
        _reset()
        runner.invoke(app, ["init"])
        runner.invoke(app, [
            "observe", "--src", "64496-10.0.1.10", "--dst", "64497-10.0.1.1",
        ])
        with tempfile.NamedTemporaryFile(suffix=".nf8", delete=False) as f:
            path = f.name
        try:
            result = runner.invoke(app, ["export", "--all", "--output", path, "--json"])
            assert result.exit_code == 0
            data = json.loads(result.output)
            assert data["exported"] == 1
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# read-nf8
# ---------------------------------------------------------------------------


class TestReadNf8:
    def test_read_nf8(self) -> None:
        _reset()
        runner.invoke(app, ["init"])
        runner.invoke(app, [
            "observe", "--src", "64496-10.0.1.10", "--dst", "64497-10.0.1.1",
        ])
        with tempfile.NamedTemporaryFile(suffix=".nf8", delete=False) as f:
            path = f.name
        try:
            runner.invoke(app, ["export", "--all", "--output", path])
            result = runner.invoke(app, ["read-nf8", path, "--json"])
            assert result.exit_code == 0
            data = json.loads(result.output)
            assert len(data) == 1
        finally:
            os.unlink(path)

    def test_read_nf8_not_found(self) -> None:
        result = runner.invoke(app, ["read-nf8", "/tmp/nonexistent.nf8"])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# top
# ---------------------------------------------------------------------------


class TestTop:
    def test_top_empty(self) -> None:
        _reset()
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["top"])
        assert result.exit_code == 0
        assert "No flows" in result.output

    def test_top_json(self) -> None:
        _reset()
        runner.invoke(app, ["init"])
        runner.invoke(app, [
            "observe", "--src", "64496-10.0.1.10", "--dst", "64497-10.0.1.1",
            "--count", "10",
        ])
        runner.invoke(app, [
            "observe", "--src", "64496-10.0.1.20", "--dst", "64497-10.0.1.1",
            "--count", "5",
        ])
        result = runner.invoke(app, ["top", "--count", "2", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 2
        assert data[0]["packets"] >= data[1]["packets"]

    def test_top_by_octets(self) -> None:
        _reset()
        runner.invoke(app, ["init"])
        runner.invoke(app, [
            "observe", "--src", "64496-10.0.1.10", "--dst", "64497-10.0.1.1",
            "--count", "5",
        ])
        result = runner.invoke(app, ["top", "--by", "octets", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) >= 1


# ---------------------------------------------------------------------------
# protocols
# ---------------------------------------------------------------------------


class TestProtocols:
    def test_protocols_empty(self) -> None:
        _reset()
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["protocols"])
        assert result.exit_code == 0
        assert "No traffic" in result.output

    def test_protocols_json(self) -> None:
        _reset()
        runner.invoke(app, ["init"])
        runner.invoke(app, [
            "observe", "--src", "64496-10.0.1.10", "--dst", "64497-10.0.1.1",
        ])
        result = runner.invoke(app, ["protocols", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "253" in data


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


class TestStatus:
    def test_status(self) -> None:
        _reset()
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["status"])
        assert result.exit_code == 0
        assert "NetFlow8" in result.output

    def test_status_json(self) -> None:
        _reset()
        runner.invoke(app, ["init"])
        runner.invoke(app, [
            "observe", "--src", "64496-10.0.1.10", "--dst", "64497-10.0.1.1",
        ])
        result = runner.invoke(app, ["status", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["stats"]["active_flows"] == 1


# ---------------------------------------------------------------------------
# demo
# ---------------------------------------------------------------------------


class TestDemo:
    def test_demo(self) -> None:
        _reset()
        result = runner.invoke(app, ["demo"])
        assert result.exit_code == 0
        assert "NetFlow8" in result.output

    def test_demo_json(self) -> None:
        _reset()
        result = runner.invoke(app, ["demo", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["flows_exported"] == 4
        assert len(data["records"]) == 4
