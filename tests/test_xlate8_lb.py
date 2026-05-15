# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for XLATE8 Even/Odd Load Balancing per Section 15.1."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from ipv8lab.address import IPv8Address
from ipv8lab.xlate8_lb import (
    EvenOddLB,
    LBStrategy,
    Parity,
    address_parity,
    make_a8_pair,
)
from ipv8lab.cli.xlate8_lb_cli import app

runner = CliRunner()


# ===================================================================
# Parity
# ===================================================================

class TestParity:
    def test_even(self) -> None:
        addr = IPv8Address.parse("64496.10.0.0.2")
        assert address_parity(addr) == Parity.EVEN

    def test_odd(self) -> None:
        addr = IPv8Address.parse("64496.10.0.0.3")
        assert address_parity(addr) == Parity.ODD

    def test_zero_is_even(self) -> None:
        addr = IPv8Address.parse("64496.10.0.0.0")
        assert address_parity(addr) == Parity.EVEN


# ===================================================================
# A8Pair
# ===================================================================

class TestA8Pair:
    def test_make_a8_pair(self) -> None:
        pair = make_a8_pair(64496, "10.0.0")
        assert address_parity(pair.even) == Parity.EVEN
        assert address_parity(pair.odd) == Parity.ODD

    def test_to_dict(self) -> None:
        pair = make_a8_pair(64496, "10.0.0")
        d = pair.to_dict()
        assert "even" in d
        assert "odd" in d

    def test_invalid_host_base(self) -> None:
        try:
            make_a8_pair(64496, "10.0")
            raise AssertionError("should fail")
        except ValueError:
            pass

    def test_pair_same_asn(self) -> None:
        pair = make_a8_pair(64497, "192.168.1")
        assert pair.even.asn == 64497
        assert pair.odd.asn == 64497


# ===================================================================
# EvenOddLB
# ===================================================================

class TestEvenOddLB:
    def test_round_robin_alternates(self) -> None:
        pair = make_a8_pair(64496, "10.0.0")
        lb = EvenOddLB(pair=pair, strategy=LBStrategy.ROUND_ROBIN)
        c1 = lb.select()
        c2 = lb.select()
        assert c1.parity != c2.parity

    def test_round_robin_distribution(self) -> None:
        pair = make_a8_pair(64496, "10.0.0")
        lb = EvenOddLB(pair=pair, strategy=LBStrategy.ROUND_ROBIN)
        conns = lb.distribute("192.168.1.1", 10)
        parities = [c.parity for c in conns]
        assert parities.count(Parity.EVEN) == 5
        assert parities.count(Parity.ODD) == 5

    def test_even_only(self) -> None:
        pair = make_a8_pair(64496, "10.0.0")
        lb = EvenOddLB(pair=pair, strategy=LBStrategy.EVEN_ONLY)
        conns = lb.distribute("192.168.1.1", 5)
        assert all(c.parity == Parity.EVEN for c in conns)

    def test_odd_only(self) -> None:
        pair = make_a8_pair(64496, "10.0.0")
        lb = EvenOddLB(pair=pair, strategy=LBStrategy.ODD_ONLY)
        conns = lb.distribute("192.168.1.1", 5)
        assert all(c.parity == Parity.ODD for c in conns)

    def test_passthrough_alternates(self) -> None:
        pair = make_a8_pair(64496, "10.0.0")
        lb = EvenOddLB(pair=pair, strategy=LBStrategy.PASSTHROUGH)
        c1 = lb.select()
        c2 = lb.select()
        assert c1.parity != c2.parity

    def test_stats(self) -> None:
        pair = make_a8_pair(64496, "10.0.0")
        lb = EvenOddLB(pair=pair)
        lb.distribute("1.2.3.4", 6)
        s = lb.stats
        assert s["total"] == 6
        assert s["even"] == 3
        assert s["odd"] == 3

    def test_reset(self) -> None:
        pair = make_a8_pair(64496, "10.0.0")
        lb = EvenOddLB(pair=pair)
        lb.distribute("1.2.3.4", 4)
        lb.reset()
        assert lb.stats["total"] == 0

    def test_connections_list(self) -> None:
        pair = make_a8_pair(64496, "10.0.0")
        lb = EvenOddLB(pair=pair)
        lb.select("1.2.3.4", 80)
        assert len(lb.connections) == 1
        assert lb.connections[0].client_addr == "1.2.3.4"

    def test_summary(self) -> None:
        pair = make_a8_pair(64496, "10.0.0")
        lb = EvenOddLB(pair=pair)
        d = lb.summary()
        assert d["strategy"] == "round_robin"
        assert "pair" in d
        assert "stats" in d

    def test_seq_increments(self) -> None:
        pair = make_a8_pair(64496, "10.0.0")
        lb = EvenOddLB(pair=pair)
        c1 = lb.select()
        c2 = lb.select()
        c3 = lb.select()
        assert c1.seq == 0
        assert c2.seq == 1
        assert c3.seq == 2


# ===================================================================
# CLI tests
# ===================================================================

class TestXLATE8LBCLI:
    def test_init_json(self) -> None:
        result = runner.invoke(app, ["init", "--asn", "64496", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["strategy"] == "round_robin"

    def test_init_text(self) -> None:
        result = runner.invoke(app, ["init", "--asn", "64496"])
        assert result.exit_code == 0
        assert "even=" in result.output

    def test_connect_json(self) -> None:
        runner.invoke(app, ["init", "--asn", "64496"])
        result = runner.invoke(app, ["connect", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["parity"] in ("even", "odd")

    def test_simulate_json(self) -> None:
        runner.invoke(app, ["init", "--asn", "64496"])
        result = runner.invoke(app, ["simulate", "--count", "6", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["stats"]["total"] == 6
        assert data["stats"]["even"] == 3
        assert data["stats"]["odd"] == 3

    def test_simulate_text(self) -> None:
        runner.invoke(app, ["init", "--asn", "64496"])
        result = runner.invoke(app, ["simulate", "--count", "4"])
        assert result.exit_code == 0
        assert "Even:" in result.output

    def test_stats_json(self) -> None:
        runner.invoke(app, ["init", "--asn", "64496"])
        runner.invoke(app, ["simulate", "--count", "4"])
        result = runner.invoke(app, ["stats", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "total" in data

    def test_status_json(self) -> None:
        runner.invoke(app, ["init", "--asn", "64496"])
        result = runner.invoke(app, ["status", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["strategy"] == "round_robin"

    def test_even_only_strategy(self) -> None:
        runner.invoke(app, ["init", "--asn", "64496", "--strategy", "even_only"])
        result = runner.invoke(app, ["simulate", "--count", "4", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["stats"]["even"] == 4
        assert data["stats"]["odd"] == 0

    def test_no_args_help(self) -> None:
        result = runner.invoke(app, [])
        assert result.exit_code in (0, 2)
