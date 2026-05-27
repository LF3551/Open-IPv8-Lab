# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for BGP8 path selection CLI."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from ipv8lab.cli import bgp8_cli
from ipv8lab.cli.bgp8_cli import app

runner = CliRunner()


def _reset() -> None:
    bgp8_cli._selector = None


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------

class TestInit:
    def setup_method(self) -> None:
        _reset()

    def test_init_default(self) -> None:
        result = runner.invoke(app, ["init"])
        assert result.exit_code == 0
        assert "64496" in result.output

    def test_init_custom_asn(self) -> None:
        result = runner.invoke(app, ["init", "--asn", "64500"])
        assert result.exit_code == 0
        assert "64500" in result.output

    def test_init_json(self) -> None:
        result = runner.invoke(app, ["init", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["status"] == "initialized"
        assert data["local_asn"] == 64496

    def test_init_with_intrazone_cf(self) -> None:
        result = runner.invoke(app, ["init", "--intrazone-cf", "1000", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["intrazone_cf"] == 1000

    def test_init_resets_state(self) -> None:
        runner.invoke(app, ["init", "--asn", "64497"])
        runner.invoke(app, ["add-peer", "64498", "64498-10.0.1.1"])
        runner.invoke(app, ["init", "--asn", "64496", "--json"])
        result = runner.invoke(app, ["status", "--json"])
        data = json.loads(result.output)
        assert data["peers"] == 0


# ---------------------------------------------------------------------------
# add-peer
# ---------------------------------------------------------------------------

class TestAddPeer:
    def setup_method(self) -> None:
        _reset()

    def test_add_peer(self) -> None:
        result = runner.invoke(app, ["add-peer", "64497", "64497-10.0.1.1"])
        assert result.exit_code == 0
        assert "64497" in result.output

    def test_add_peer_json(self) -> None:
        result = runner.invoke(app, ["add-peer", "64497", "64497-10.0.1.1", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["asn"] == 64497
        assert data["is_ebgp"] is True
        assert data["total_peers"] == 1

    def test_add_ibgp_peer(self) -> None:
        result = runner.invoke(app, ["add-peer", "64497", "64497-10.0.1.1", "--ibgp", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["is_ebgp"] is False

    def test_add_peer_with_desc(self) -> None:
        result = runner.invoke(app, ["add-peer", "64497", "64497-10.0.1.1", "--desc", "upstream", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["description"] == "upstream"


# ---------------------------------------------------------------------------
# advertise
# ---------------------------------------------------------------------------

class TestAdvertise:
    def setup_method(self) -> None:
        _reset()

    def test_advertise_simple(self) -> None:
        result = runner.invoke(app, ["advertise", "64497-0.0.0.0/8", "64497"])
        assert result.exit_code == 0
        assert "accepted" in result.output.lower()

    def test_advertise_json(self) -> None:
        result = runner.invoke(app, ["advertise", "64497-0.0.0.0/8", "64497", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["accepted"] is True
        assert data["prefix"] == "64497-0.0.0.0/8"
        assert data["rib_size"] == 1

    def test_advertise_with_as_path(self) -> None:
        result = runner.invoke(app, [
            "advertise", "64497-0.0.0.0/8", "64497",
            "--as-path", "64498,64497", "--json",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["as_path"] == [64498, 64497]

    def test_advertise_with_cf_components(self) -> None:
        result = runner.invoke(app, [
            "advertise", "64497-0.0.0.0/8", "64497",
            "--rtt", "0.2", "--packet-loss", "0.1", "--json",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["cf_value"] > 0

    def test_advertise_with_hop_cfs(self) -> None:
        result = runner.invoke(app, [
            "advertise", "64497-0.0.0.0/8", "64497",
            "--hop-cfs", "100,200", "--json",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["hop_cfs"] == [100, 200]

    def test_advertise_loop_rejected(self) -> None:
        runner.invoke(app, ["init", "--asn", "64496"])
        result = runner.invoke(app, [
            "advertise", "64497-0.0.0.0/8", "64497",
            "--as-path", "64496,64497", "--json",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["accepted"] is False

    def test_advertise_invalid_prefix_length(self) -> None:
        result = runner.invoke(app, [
            "advertise", "64497-0.0.0.0/32", "64497",
            "--prefix-len", "32", "--json",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["accepted"] is False

    def test_advertise_bad_cf_component(self) -> None:
        result = runner.invoke(app, [
            "advertise", "64497-0.0.0.0/8", "64497",
            "--rtt", "1.5",
        ])
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# withdraw
# ---------------------------------------------------------------------------

class TestWithdraw:
    def setup_method(self) -> None:
        _reset()

    def test_withdraw(self) -> None:
        runner.invoke(app, ["advertise", "64497-0.0.0.0/8", "64497"])
        result = runner.invoke(app, ["withdraw", "64497-0.0.0.0/8", "64497", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["withdrawn"] is True

    def test_withdraw_nonexistent(self) -> None:
        result = runner.invoke(app, ["withdraw", "64497-0.0.0.0/8", "64497", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["withdrawn"] is False

    def test_withdraw_rich(self) -> None:
        result = runner.invoke(app, ["withdraw", "64497-0.0.0.0/8", "64497"])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# select
# ---------------------------------------------------------------------------

class TestSelect:
    def setup_method(self) -> None:
        _reset()

    def test_select_no_paths(self) -> None:
        result = runner.invoke(app, ["select", "64497-0.0.0.0/8", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["best"] is None
        assert data["reason"] == "no paths"

    def test_select_one_path(self) -> None:
        runner.invoke(app, ["advertise", "64497-0.0.0.0/8", "64497", "--hop-cfs", "100"])
        result = runner.invoke(app, ["select", "64497-0.0.0.0/8", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["best"]["origin_asn"] == 64497
        assert data["best"]["accumulated_cf"] == 100

    def test_select_best_cf_wins(self) -> None:
        runner.invoke(app, ["advertise", "64497-0.0.0.0/8", "64497",
                            "--as-path", "64497", "--hop-cfs", "500"])
        runner.invoke(app, ["advertise", "64497-0.0.0.0/8", "64497",
                            "--as-path", "64498,64497", "--hop-cfs", "100"])
        result = runner.invoke(app, ["select", "64497-0.0.0.0/8", "--json"])
        data = json.loads(result.output)
        assert data["best"]["accumulated_cf"] == 100

    def test_select_rich(self) -> None:
        runner.invoke(app, ["advertise", "64497-0.0.0.0/8", "64497", "--hop-cfs", "50"])
        result = runner.invoke(app, ["select", "64497-0.0.0.0/8"])
        assert result.exit_code == 0
        assert "64497" in result.output

    def test_select_no_path_rich(self) -> None:
        result = runner.invoke(app, ["select", "64497-0.0.0.0/8"])
        assert result.exit_code == 0
        assert "No path" in result.output


# ---------------------------------------------------------------------------
# rib
# ---------------------------------------------------------------------------

class TestRib:
    def setup_method(self) -> None:
        _reset()

    def test_rib_empty(self) -> None:
        result = runner.invoke(app, ["rib"])
        assert result.exit_code == 0
        assert "empty" in result.output.lower()

    def test_rib_empty_json(self) -> None:
        result = runner.invoke(app, ["rib", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data == []

    def test_rib_after_advertise(self) -> None:
        runner.invoke(app, ["advertise", "64497-0.0.0.0/8", "64497"])
        runner.invoke(app, ["advertise", "64499-0.0.0.0/8", "64499"])
        result = runner.invoke(app, ["rib", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 2

    def test_rib_rich(self) -> None:
        runner.invoke(app, ["advertise", "64497-0.0.0.0/8", "64497"])
        result = runner.invoke(app, ["rib"])
        assert result.exit_code == 0
        assert "64497" in result.output


# ---------------------------------------------------------------------------
# peers
# ---------------------------------------------------------------------------

class TestPeers:
    def setup_method(self) -> None:
        _reset()

    def test_peers_empty(self) -> None:
        result = runner.invoke(app, ["peers"])
        assert result.exit_code == 0
        assert "No peers" in result.output

    def test_peers_empty_json(self) -> None:
        result = runner.invoke(app, ["peers", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data == []

    def test_peers_after_add(self) -> None:
        runner.invoke(app, ["add-peer", "64497", "64497-10.0.1.1"])
        runner.invoke(app, ["add-peer", "64498", "64498-10.0.1.1", "--ibgp"])
        result = runner.invoke(app, ["peers", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 2
        assert data[0]["is_ebgp"] is True
        assert data[1]["is_ebgp"] is False

    def test_peers_rich(self) -> None:
        runner.invoke(app, ["add-peer", "64497", "64497-10.0.1.1"])
        result = runner.invoke(app, ["peers"])
        assert result.exit_code == 0
        assert "64497" in result.output


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
        assert data["local_asn"] == 64496
        assert data["peers"] == 0
        assert data["rib_size"] == 0

    def test_status_after_ops(self) -> None:
        runner.invoke(app, ["add-peer", "64497", "64497-10.0.1.1"])
        runner.invoke(app, ["advertise", "64497-0.0.0.0/8", "64497"])
        result = runner.invoke(app, ["status", "--json"])
        data = json.loads(result.output)
        assert data["peers"] == 1
        assert data["rib_size"] == 1
        assert data["prefixes"] == 1

    def test_status_rich(self) -> None:
        result = runner.invoke(app, ["status"])
        assert result.exit_code == 0
        assert "Local ASN" in result.output


# ---------------------------------------------------------------------------
# demo
# ---------------------------------------------------------------------------

class TestDemo:
    def setup_method(self) -> None:
        _reset()

    def test_demo(self) -> None:
        result = runner.invoke(app, ["demo"])
        assert result.exit_code == 0
        assert "Demo" in result.output or "complete" in result.output.lower()

    def test_demo_json(self) -> None:
        result = runner.invoke(app, ["demo", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["local_asn"] == 64496
        assert data["peers"] == 3
        assert len(data["prefixes"]) == 2
        for pfx_data in data["prefixes"].values():
            assert "best" in pfx_data

    def test_demo_resets_state(self) -> None:
        runner.invoke(app, ["add-peer", "99999", "99999.10.0.1.1"])
        runner.invoke(app, ["demo", "--json"])
        result = runner.invoke(app, ["peers", "--json"])
        data = json.loads(result.output)
        asns = {p["asn"] for p in data}
        assert 99999 not in asns
