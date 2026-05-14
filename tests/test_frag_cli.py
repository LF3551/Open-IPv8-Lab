# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for fragmentation CLI commands."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from ipv8lab.cli.frag_cli import app

runner = CliRunner()


# ---------------------------------------------------------------------------
# fragment
# ---------------------------------------------------------------------------

class TestFragmentCmd:
    def test_fragment(self) -> None:
        result = runner.invoke(app, ["fragment", "--size", "3000", "--mtu", "1500"])
        assert result.exit_code == 0
        assert "fragments" in result.output.lower() or "✓" in result.output

    def test_fragment_json(self) -> None:
        result = runner.invoke(app, ["fragment", "--size", "3000", "--mtu", "1500", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["count"] >= 2
        assert data["mtu"] == 1500

    def test_fragment_no_split(self) -> None:
        result = runner.invoke(app, ["fragment", "--size", "100", "--mtu", "1500", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["count"] == 1

    def test_fragment_tiny_mtu(self) -> None:
        result = runner.invoke(app, ["fragment", "--size", "1000", "--mtu", "64", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["count"] > 10

    def test_fragment_bad_addr(self) -> None:
        result = runner.invoke(app, ["fragment", "--src", "bad"])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# reassemble
# ---------------------------------------------------------------------------

class TestReassembleCmd:
    def test_reassemble(self) -> None:
        result = runner.invoke(app, ["reassemble", "--size", "3000", "--mtu", "1500"])
        assert result.exit_code == 0
        assert "PASS" in result.output or "✓" in result.output

    def test_reassemble_json(self) -> None:
        result = runner.invoke(app, ["reassemble", "--size", "3000", "--mtu", "1500", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["payload_match"] is True
        assert data["fragments"] >= 2

    def test_reassemble_small(self) -> None:
        result = runner.invoke(app, ["reassemble", "--size", "100", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["payload_match"] is True

    def test_reassemble_bad_addr(self) -> None:
        result = runner.invoke(app, ["reassemble", "--dst", "invalid"])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# info
# ---------------------------------------------------------------------------

class TestInfoCmd:
    def test_info(self) -> None:
        result = runner.invoke(app, ["info", "--size", "3000", "--mtu", "1500"])
        assert result.exit_code == 0
        assert "Fragmentation Info" in result.output

    def test_info_json(self) -> None:
        result = runner.invoke(app, ["info", "--size", "3000", "--mtu", "1500", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["needs_fragmentation"] is True
        assert data["can_fragment"] is True
        assert data["estimated_fragments"] >= 2

    def test_info_df(self) -> None:
        result = runner.invoke(app, ["info", "--size", "3000", "--df", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["df_flag"] is True
        assert data["can_fragment"] is False

    def test_info_no_frag_needed(self) -> None:
        result = runner.invoke(app, ["info", "--size", "100", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["needs_fragmentation"] is False


# ---------------------------------------------------------------------------
# demo
# ---------------------------------------------------------------------------

class TestDemoCmd:
    def test_demo(self) -> None:
        result = runner.invoke(app, ["demo"])
        assert result.exit_code == 0
        assert "Fragmentation Demo" in result.output

    def test_demo_json(self) -> None:
        result = runner.invoke(app, ["demo", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data["scenarios"]) == 6
        for s in data["scenarios"]:
            assert s["match"] is True
