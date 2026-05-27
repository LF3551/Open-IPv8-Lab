# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for QoS CLI commands."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from ipv8lab.cli.qos_cli import _reset, app

runner = CliRunner()


def setup_function() -> None:
    _reset()


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------


class TestInit:
    def test_init_priority(self) -> None:
        _reset()
        result = runner.invoke(app, ["init"])
        assert result.exit_code == 0
        assert "PRIORITY" in result.output

    def test_init_wfq(self) -> None:
        _reset()
        result = runner.invoke(app, ["init", "--policy", "wfq"])
        assert result.exit_code == 0
        assert "WFQ" in result.output

    def test_init_fifo(self) -> None:
        _reset()
        result = runner.invoke(app, ["init", "--policy", "fifo"])
        assert result.exit_code == 0

    def test_init_json(self) -> None:
        _reset()
        result = runner.invoke(app, ["init", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["policy"] == "PRIORITY"

    def test_init_bad_policy(self) -> None:
        _reset()
        result = runner.invoke(app, ["init", "--policy", "bad"])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# configure
# ---------------------------------------------------------------------------


class TestConfigure:
    def test_configure(self) -> None:
        _reset()
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["configure", "EF", "--rate", "1000000", "--weight", "5"])
        assert result.exit_code == 0
        assert "EF" in result.output

    def test_configure_json(self) -> None:
        _reset()
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["configure", "BE", "--rate", "500000", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["traffic_class"] == "BE"
        assert data["rate_bps"] == 500000

    def test_configure_bad_class(self) -> None:
        _reset()
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["configure", "INVALID"])
        assert result.exit_code != 0

    def test_configure_no_init(self) -> None:
        _reset()
        result = runner.invoke(app, ["configure", "EF"])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# classify
# ---------------------------------------------------------------------------


class TestClassify:
    def test_classify_be(self) -> None:
        _reset()
        result = runner.invoke(app, [
            "classify", "--src", "64496-10.0.1.10", "--dst", "64497-10.0.1.1", "--tos", "0",
        ])
        assert result.exit_code == 0
        assert "BE" in result.output

    def test_classify_ef(self) -> None:
        _reset()
        result = runner.invoke(app, [
            "classify", "--src", "64496-10.0.1.10", "--dst", "64497-10.0.1.1", "--tos", "184",
        ])
        assert result.exit_code == 0
        assert "EF" in result.output

    def test_classify_json(self) -> None:
        _reset()
        result = runner.invoke(app, [
            "classify", "--src", "64496-10.0.1.10", "--dst", "64497-10.0.1.1",
            "--tos", "184", "--json",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["traffic_class"] == "EF"
        assert data["dscp"] == 46


# ---------------------------------------------------------------------------
# enqueue
# ---------------------------------------------------------------------------


class TestEnqueue:
    def test_enqueue(self) -> None:
        _reset()
        runner.invoke(app, ["init"])
        result = runner.invoke(app, [
            "enqueue", "--src", "64496-10.0.1.10", "--dst", "64497-10.0.1.1",
        ])
        assert result.exit_code == 0
        assert "1/1" in result.output

    def test_enqueue_multiple(self) -> None:
        _reset()
        runner.invoke(app, ["init"])
        result = runner.invoke(app, [
            "enqueue", "--src", "64496-10.0.1.10", "--dst", "64497-10.0.1.1",
            "--count", "5",
        ])
        assert result.exit_code == 0
        assert "5/5" in result.output

    def test_enqueue_json(self) -> None:
        _reset()
        runner.invoke(app, ["init"])
        result = runner.invoke(app, [
            "enqueue", "--src", "64496-10.0.1.10", "--dst", "64497-10.0.1.1",
            "--tos", "184", "--json",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["enqueued"] == 1
        assert data["queue_depth"] == 1

    def test_enqueue_no_init(self) -> None:
        _reset()
        result = runner.invoke(app, [
            "enqueue", "--src", "64496-10.0.1.10", "--dst", "64497-10.0.1.1",
        ])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# dequeue
# ---------------------------------------------------------------------------


class TestDequeue:
    def test_dequeue(self) -> None:
        _reset()
        runner.invoke(app, ["init"])
        runner.invoke(app, ["enqueue", "--src", "64496-10.0.1.10", "--dst", "64497-10.0.1.1"])
        result = runner.invoke(app, ["dequeue"])
        assert result.exit_code == 0
        assert "1" in result.output

    def test_dequeue_json(self) -> None:
        _reset()
        runner.invoke(app, ["init"])
        runner.invoke(app, [
            "enqueue", "--src", "64496-10.0.1.10", "--dst", "64497-10.0.1.1", "--tos", "184",
        ])
        result = runner.invoke(app, ["dequeue", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["dequeued"] == 1
        assert data["packets"][0]["class"] == "EF"

    def test_dequeue_empty(self) -> None:
        _reset()
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["dequeue"])
        assert result.exit_code == 0
        assert "empty" in result.output.lower()


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


class TestStatus:
    def test_status(self) -> None:
        _reset()
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["status"])
        assert result.exit_code == 0
        assert "QoS" in result.output

    def test_status_json(self) -> None:
        _reset()
        runner.invoke(app, ["init"])
        runner.invoke(app, ["enqueue", "--src", "64496-10.0.1.10", "--dst", "64497-10.0.1.1"])
        result = runner.invoke(app, ["status", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["policy"] == "PRIORITY"
        assert data["stats"]["total_enqueued"] == 1


# ---------------------------------------------------------------------------
# queues
# ---------------------------------------------------------------------------


class TestQueues:
    def test_queues(self) -> None:
        _reset()
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["queues"])
        assert result.exit_code == 0

    def test_queues_json(self) -> None:
        _reset()
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["queues", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == len(list(range(8)))  # 8 traffic classes


# ---------------------------------------------------------------------------
# demo
# ---------------------------------------------------------------------------


class TestDemo:
    def test_demo(self) -> None:
        _reset()
        result = runner.invoke(app, ["demo"])
        assert result.exit_code == 0
        assert "PRIORITY" in result.output

    def test_demo_json(self) -> None:
        _reset()
        result = runner.invoke(app, ["demo", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data["scenarios"]) == 3
