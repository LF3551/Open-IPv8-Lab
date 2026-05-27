# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for Docker testbed CLI."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from ipv8lab.cli.docker_cli import _reset, app

runner = CliRunner()


@pytest.fixture(autouse=True)
def _reset_state() -> None:
    _reset()


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------


class TestInit:
    def test_init_default(self) -> None:
        result = runner.invoke(app, ["init"])
        assert result.exit_code == 0
        assert "initialized" in result.output

    def test_init_named(self) -> None:
        result = runner.invoke(app, ["init", "--name", "lab-01"])
        assert result.exit_code == 0
        assert "lab-01" in result.output

    def test_init_json(self) -> None:
        result = runner.invoke(app, ["init", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["name"] == "ipv8-testbed"

    def test_init_two_asn(self) -> None:
        result = runner.invoke(app, ["init", "--topology", "two-asn", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["stats"]["node_count"] == 6

    def test_init_star(self) -> None:
        result = runner.invoke(app, ["init", "--topology", "star", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["stats"]["node_count"] == 5

    def test_init_mesh(self) -> None:
        result = runner.invoke(app, ["init", "--topology", "mesh", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["stats"]["node_count"] == 4

    def test_init_bad_topology(self) -> None:
        result = runner.invoke(app, ["init", "--topology", "invalid"])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# add-node
# ---------------------------------------------------------------------------


class TestAddNode:
    def test_add_node(self) -> None:
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["add-node", "r1", "--addr", "64496-10.0.1.1", "--role", "router"])
        assert result.exit_code == 0
        assert "r1" in result.output

    def test_add_node_json(self) -> None:
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["add-node", "h1", "--addr", "64496-10.0.1.10", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["name"] == "h1"
        assert data["role"] == "host"

    def test_add_node_bad_role(self) -> None:
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["add-node", "x", "--addr", "64496-10.0.1.1", "--role", "INVALID"])
        assert result.exit_code != 0

    def test_add_node_no_init(self) -> None:
        result = runner.invoke(app, ["add-node", "r1", "--addr", "64496-10.0.1.1"])
        assert result.exit_code != 0 or "not initialized" in result.output


# ---------------------------------------------------------------------------
# add-link
# ---------------------------------------------------------------------------


class TestAddLink:
    def test_add_link(self) -> None:
        runner.invoke(app, ["init"])
        runner.invoke(app, ["add-node", "r1", "--addr", "64496-10.0.1.1", "--role", "router"])
        runner.invoke(app, ["add-node", "h1", "--addr", "64496-10.0.1.10"])
        result = runner.invoke(app, ["add-link", "r1", "h1", "--net", "10.0.1.0/24"])
        assert result.exit_code == 0
        assert "r1" in result.output

    def test_add_link_json(self) -> None:
        runner.invoke(app, ["init"])
        runner.invoke(app, ["add-node", "r1", "--addr", "64496-10.0.1.1"])
        runner.invoke(app, ["add-node", "h1", "--addr", "64496-10.0.1.10"])
        result = runner.invoke(app, ["add-link", "r1", "h1", "--net", "10.0.1.0/24", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["node_a"] == "r1"

    def test_add_link_custom_name(self) -> None:
        runner.invoke(app, ["init"])
        runner.invoke(app, ["add-node", "r1", "--addr", "64496-10.0.1.1"])
        runner.invoke(app, ["add-node", "h1", "--addr", "64496-10.0.1.10"])
        result = runner.invoke(app, ["add-link", "r1", "h1", "--net", "10.0.1.0/24", "--name", "mynet", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["network_name"] == "mynet"

    def test_add_link_no_init(self) -> None:
        result = runner.invoke(app, ["add-link", "r1", "h1", "--net", "10.0.1.0/24"])
        assert result.exit_code != 0 or "not initialized" in result.output


# ---------------------------------------------------------------------------
# topology
# ---------------------------------------------------------------------------


class TestTopology:
    def test_topology_empty(self) -> None:
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["topology"])
        assert result.exit_code == 0
        assert "No nodes" in result.output

    def test_topology_json(self) -> None:
        runner.invoke(app, ["init", "--topology", "two-asn"])
        result = runner.invoke(app, ["topology", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data["nodes"]) == 6

    def test_topology_with_nodes(self) -> None:
        runner.invoke(app, ["init"])
        runner.invoke(app, ["add-node", "r1", "--addr", "64496-10.0.1.1", "--role", "router"])
        result = runner.invoke(app, ["topology"])
        assert result.exit_code == 0
        assert "r1" in result.output


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


class TestStatus:
    def test_status(self) -> None:
        runner.invoke(app, ["init", "--topology", "star"])
        result = runner.invoke(app, ["status"])
        assert result.exit_code == 0
        assert "Nodes" in result.output

    def test_status_json(self) -> None:
        runner.invoke(app, ["init", "--topology", "mesh"])
        result = runner.invoke(app, ["status", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["stats"]["node_count"] == 4


# ---------------------------------------------------------------------------
# generate
# ---------------------------------------------------------------------------


class TestGenerate:
    def test_generate(self) -> None:
        runner.invoke(app, ["init", "--topology", "star"])
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            result = runner.invoke(app, ["generate", "--output", tmpdir])
            assert result.exit_code == 0
            assert "Generated" in result.output

    def test_generate_json(self) -> None:
        runner.invoke(app, ["init", "--topology", "star"])
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            result = runner.invoke(app, ["generate", "--output", tmpdir, "--json"])
            assert result.exit_code == 0
            data = json.loads(result.output)
            assert "files" in data
            assert len(data["files"]) > 0

    def test_generate_no_init(self) -> None:
        result = runner.invoke(app, ["generate"])
        assert result.exit_code != 0 or "not initialized" in result.output


# ---------------------------------------------------------------------------
# compose
# ---------------------------------------------------------------------------


class TestCompose:
    def test_compose(self) -> None:
        runner.invoke(app, ["init", "--topology", "star"])
        result = runner.invoke(app, ["compose"])
        assert result.exit_code == 0
        assert "services:" in result.output

    def test_compose_json(self) -> None:
        runner.invoke(app, ["init", "--topology", "two-asn"])
        result = runner.invoke(app, ["compose", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "services" in data
        assert "networks" in data


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
        assert len(data["scenarios"]) == 3
        assert data["scenarios"][0]["topology"] == "two-asn"
