# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for Interior Link Convention per draft-thain-ipv8-02 Section 4.10."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from ipv8lab.address import IPv8Address
from ipv8lab.interior_link import (
    INTERIOR_LINK_PREFIX,
    check_interior_link_egress,
    is_interior_link_address,
    make_interior_link,
    make_interior_links,
    summarize_interior_links,
    validate_interior_link,
)
from ipv8lab.cli.interior_link_cli import app


runner = CliRunner()


# ===================================================================
# is_interior_link_address
# ===================================================================

class TestIsInteriorLink:
    def test_true(self) -> None:
        addr = IPv8Address.parse("0.0.251.240.222.0.0.1")
        assert is_interior_link_address(addr) is True

    def test_false(self) -> None:
        addr = IPv8Address.parse("0.0.251.240.10.0.0.1")
        assert is_interior_link_address(addr) is False

    def test_prefix_constant(self) -> None:
        assert INTERIOR_LINK_PREFIX == 222


# ===================================================================
# make_interior_link
# ===================================================================

class TestMakeInteriorLink:
    def test_basic(self) -> None:
        pair = make_interior_link(64496, 0)
        assert pair.side_a.host_part[0] == 222
        assert pair.side_b.host_part[0] == 222
        assert pair.side_a.host_part[3] == 0
        assert pair.side_b.host_part[3] == 1
        assert pair.asn == 64496

    def test_link_id_1(self) -> None:
        pair = make_interior_link(64496, 1)
        assert pair.side_a.host_part[2] == 1
        assert pair.link_id == 1

    def test_high_link_id(self) -> None:
        pair = make_interior_link(64496, 256)
        assert pair.side_a.host_part[1] == 1
        assert pair.side_a.host_part[2] == 0

    def test_label(self) -> None:
        pair = make_interior_link(64496, 0, label="spine-leaf-1")
        assert pair.label == "spine-leaf-1"

    def test_asn_prefix_property(self) -> None:
        pair = make_interior_link(64496, 0)
        assert pair.asn_prefix == "0.0.251.240"

    def test_both_sides_same_asn(self) -> None:
        pair = make_interior_link(64497, 0)
        assert pair.side_a.asn == 64497
        assert pair.side_b.asn == 64497

    def test_frozen(self) -> None:
        pair = make_interior_link(64496, 0)
        with pytest.raises(AttributeError):
            pair.asn = 1  # type: ignore[misc]


# ===================================================================
# make_interior_links (batch)
# ===================================================================

class TestMakeInteriorLinks:
    def test_count(self) -> None:
        links = make_interior_links(64496, 5)
        assert len(links) == 5

    def test_sequential_ids(self) -> None:
        links = make_interior_links(64496, 3)
        assert [lk.link_id for lk in links] == [0, 1, 2]

    def test_labels(self) -> None:
        links = make_interior_links(64496, 2)
        assert links[0].label == "link-0"
        assert links[1].label == "link-1"

    def test_zero_count(self) -> None:
        assert make_interior_links(64496, 0) == []


# ===================================================================
# validate_interior_link
# ===================================================================

class TestValidateInteriorLink:
    def test_valid(self) -> None:
        addr = IPv8Address.parse("0.0.251.240.222.0.0.1")
        assert validate_interior_link(addr) == []

    def test_not_interior_link(self) -> None:
        addr = IPv8Address.parse("0.0.251.240.10.0.0.1")
        violations = validate_interior_link(addr)
        assert len(violations) == 1
        assert "222" in violations[0]

    def test_ipv4_compat_violation(self) -> None:
        addr = IPv8Address.parse("0.0.0.0.222.0.0.1")
        violations = validate_interior_link(addr)
        assert any("0.0.0.0" in v for v in violations)

    def test_internal_zone_violation(self) -> None:
        addr = IPv8Address.parse("127.1.0.0.222.0.0.1")
        violations = validate_interior_link(addr)
        assert any("127" in v for v in violations)


# ===================================================================
# check_interior_link_egress
# ===================================================================

class TestEgressCheck:
    def test_interior_link_blocked(self) -> None:
        addr = IPv8Address.parse("0.0.251.240.222.0.0.1")
        result = check_interior_link_egress(addr)
        assert result is not None
        assert "MUST NOT" in result

    def test_non_interior_ok(self) -> None:
        addr = IPv8Address.parse("0.0.251.240.10.0.0.1")
        assert check_interior_link_egress(addr) is None


# ===================================================================
# summarize_interior_links
# ===================================================================

class TestSummary:
    def test_summary(self) -> None:
        s = summarize_interior_links(64496)
        assert s.asn == 64496
        assert "222" in s.address_range
        assert s.max_links == 8_388_608
        assert "RFC 1918" in s.convention


# ===================================================================
# CLI tests
# ===================================================================

class TestInteriorLinkCLI:
    def test_generate_json(self) -> None:
        result = runner.invoke(app, ["generate", "64496", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 1
        assert "222" in data[0]["side_a"]

    def test_generate_multiple(self) -> None:
        result = runner.invoke(app, ["generate", "64496", "--count", "3", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 3

    def test_generate_text(self) -> None:
        result = runner.invoke(app, ["generate", "64496"])
        assert result.exit_code == 0
        assert "Link 0:" in result.output

    def test_validate_interior(self) -> None:
        result = runner.invoke(app, ["validate", "0.0.251.240.222.0.0.1", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["is_interior_link"] is True
        assert data["violations"] == []

    def test_validate_not_interior(self) -> None:
        result = runner.invoke(app, ["validate", "0.0.251.240.10.0.0.1", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["is_interior_link"] is False

    def test_validate_text(self) -> None:
        result = runner.invoke(app, ["validate", "0.0.251.240.222.0.0.1"])
        assert result.exit_code == 0
        assert "interior link" in result.output

    def test_check_blocked(self) -> None:
        result = runner.invoke(app, ["check", "0.0.251.240.222.0.0.1", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["egress_violation"] is not None

    def test_check_ok(self) -> None:
        result = runner.invoke(app, ["check", "0.0.251.240.10.0.0.1", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["egress_violation"] is None

    def test_check_text(self) -> None:
        result = runner.invoke(app, ["check", "0.0.251.240.222.0.0.1"])
        assert result.exit_code == 0
        assert "BLOCKED" in result.output

    def test_summary_json(self) -> None:
        result = runner.invoke(app, ["summary", "64496", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["asn"] == 64496
        assert data["max_links"] == 8_388_608

    def test_summary_text(self) -> None:
        result = runner.invoke(app, ["summary", "64496"])
        assert result.exit_code == 0
        assert "222" in result.output

    def test_no_args_help(self) -> None:
        result = runner.invoke(app, [])
        assert result.exit_code in (0, 2)
