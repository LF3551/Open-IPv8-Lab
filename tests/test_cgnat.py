# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for CGNAT Behaviour simulation per Section 15."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from ipv8lab.address import IPv8Address
from ipv8lab.cgnat import CGNATEngine, CGNATViolation

from ipv8lab.cli.cgnat_cli import app

runner = CliRunner()


# ===================================================================
# CGNATEngine — core rules
# ===================================================================

class TestCGNATEngine:
    def test_prefix_preserved(self) -> None:
        """r.r.r.r MUST NOT be modified during translation."""
        engine = CGNATEngine(operator_asn=64496)
        addr = IPv8Address.parse("64496.10.0.0.1")
        result = engine.translate(addr)
        assert result.violation == CGNATViolation.NONE
        assert result.translated.routing_prefix == addr.routing_prefix
        assert result.translated.host_str != addr.host_str

    def test_only_host_part_translated(self) -> None:
        engine = CGNATEngine(operator_asn=64496, pool_start="198.51.100.1", pool_end="198.51.100.254")
        addr = IPv8Address.parse("64496.192.168.1.1")
        result = engine.translate(addr)
        assert result.translated.prefix_str == addr.prefix_str
        assert result.translated.host_str.startswith("198.51.100.")

    def test_no_asn_uses_zero_prefix(self) -> None:
        """Operators without ASN MUST use r.r.r.r = 0.0.0.0."""
        engine = CGNATEngine(operator_asn=0)
        addr = IPv8Address.parse("0.0.0.0.192.168.1.1")
        result = engine.translate(addr)
        assert result.violation == CGNATViolation.NONE
        assert result.translated.routing_prefix == (0, 0, 0, 0)

    def test_no_asn_nonzero_prefix_violation(self) -> None:
        """Operator without ASN receiving non-zero r.r.r.r → violation."""
        engine = CGNATEngine(operator_asn=0)
        addr = IPv8Address.parse("64496.10.0.0.1")
        result = engine.translate(addr)
        assert result.violation == CGNATViolation.NO_ASN_NONZERO_PREFIX

    def test_validate_ok(self) -> None:
        engine = CGNATEngine(operator_asn=64496)
        orig = IPv8Address.parse("64496.10.0.0.1")
        trans = IPv8Address.parse("64496.198.51.100.1")
        assert engine.validate_translation(orig, trans) == CGNATViolation.NONE

    def test_validate_prefix_modified(self) -> None:
        engine = CGNATEngine(operator_asn=64496)
        orig = IPv8Address.parse("64496.10.0.0.1")
        trans = IPv8Address.parse("64497.198.51.100.1")
        assert engine.validate_translation(orig, trans) == CGNATViolation.PREFIX_MODIFIED

    def test_bindings_recorded(self) -> None:
        engine = CGNATEngine(operator_asn=64496)
        addr = IPv8Address.parse("64496.10.0.0.1")
        engine.translate(addr, src_port=12345)
        assert len(engine.bindings) == 1
        b = engine.bindings[0]
        assert b.inside == addr
        assert b.port_inside == 12345

    def test_reverse_translate(self) -> None:
        engine = CGNATEngine(operator_asn=64496)
        addr = IPv8Address.parse("64496.10.0.0.1")
        result = engine.translate(addr)
        found = engine.reverse_translate(result.translated)
        assert found == addr

    def test_reverse_translate_miss(self) -> None:
        engine = CGNATEngine(operator_asn=64496)
        addr = IPv8Address.parse("64496.1.2.3.4")
        assert engine.reverse_translate(addr) is None

    def test_flush(self) -> None:
        engine = CGNATEngine(operator_asn=64496)
        engine.translate(IPv8Address.parse("64496.10.0.0.1"))
        engine.translate(IPv8Address.parse("64496.10.0.0.2"))
        n = engine.flush()
        assert n == 2
        assert len(engine.bindings) == 0

    def test_multiple_translations_pool_rotation(self) -> None:
        engine = CGNATEngine(operator_asn=64496, pool_start="198.51.100.1", pool_end="198.51.100.3")
        hosts = set()
        for i in range(4):
            result = engine.translate(IPv8Address.parse(f"64496.10.0.0.{i + 1}"))
            hosts.add(result.translated.host_str)
        # Pool has 3 addresses, 4th wraps around
        assert len(hosts) == 3

    def test_summary(self) -> None:
        engine = CGNATEngine(operator_asn=64496, pool_start="198.51.100.1", pool_end="198.51.100.254")
        d = engine.summary()
        assert d["operator_asn"] == 64496
        assert d["active_bindings"] == 0

    def test_operator_prefix_with_asn(self) -> None:
        engine = CGNATEngine(operator_asn=64496)
        assert engine.operator_prefix == (0, 0, 251, 240)

    def test_operator_prefix_no_asn(self) -> None:
        engine = CGNATEngine(operator_asn=0)
        assert engine.operator_prefix == (0, 0, 0, 0)

    def test_ipv4_compat_translation(self) -> None:
        """IPv4-compatible address (r.r.r.r=0) translates normally."""
        engine = CGNATEngine(operator_asn=0)
        addr = IPv8Address.parse("0.0.0.0.192.168.1.100")
        result = engine.translate(addr)
        assert result.violation == CGNATViolation.NONE
        assert result.translated.routing_prefix == (0, 0, 0, 0)


# ===================================================================
# CLI tests
# ===================================================================

class TestCGNATCLI:
    def test_init_json(self) -> None:
        result = runner.invoke(app, ["init", "--asn", "64496", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["operator_asn"] == 64496

    def test_init_text(self) -> None:
        result = runner.invoke(app, ["init", "--asn", "64496"])
        assert result.exit_code == 0
        assert "64496" in result.output

    def test_translate_json(self) -> None:
        runner.invoke(app, ["init", "--asn", "64496"])
        result = runner.invoke(app, ["translate", "64496.10.0.0.1", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["prefix_preserved"] is True
        assert data["violation"] == "none"

    def test_translate_text(self) -> None:
        runner.invoke(app, ["init", "--asn", "64496"])
        result = runner.invoke(app, ["translate", "64496.10.0.0.1"])
        assert result.exit_code == 0
        assert "preserved" in result.output.lower()

    def test_validate_json(self) -> None:
        runner.invoke(app, ["init", "--asn", "64496"])
        result = runner.invoke(app, [
            "validate", "0.0.251.240.10.0.0.1", "0.0.251.240.198.51.100.1", "--json",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["violation"] == "none"

    def test_validate_violation_json(self) -> None:
        runner.invoke(app, ["init", "--asn", "64496"])
        result = runner.invoke(app, [
            "validate", "0.0.251.240.10.0.0.1", "0.0.251.241.198.51.100.1", "--json",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["violation"] == "prefix_modified"

    def test_bindings_json(self) -> None:
        runner.invoke(app, ["init", "--asn", "64496"])
        runner.invoke(app, ["translate", "64496.10.0.0.1"])
        result = runner.invoke(app, ["bindings", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) >= 1

    def test_flush_json(self) -> None:
        runner.invoke(app, ["init", "--asn", "64496"])
        runner.invoke(app, ["translate", "64496.10.0.0.1"])
        result = runner.invoke(app, ["flush", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["flushed"] >= 1

    def test_status_json(self) -> None:
        runner.invoke(app, ["init", "--asn", "64496"])
        result = runner.invoke(app, ["status", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["operator_asn"] == 64496

    def test_no_args_help(self) -> None:
        result = runner.invoke(app, [])
        assert result.exit_code in (0, 2)
