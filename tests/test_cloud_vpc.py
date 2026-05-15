# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for Cloud Provider VPC simulation per Section 17."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from ipv8lab.address import IPv8Address
from ipv8lab.cloud_vpc import CloudVPCFabric, VPC

from ipv8lab.cli.cloud_vpc_cli import app

runner = CliRunner()


# ===================================================================
# VPC
# ===================================================================

class TestVPC:
    def test_contains(self) -> None:
        vpc = VPC(vpc_id="v1", customer="acme", zone_prefix=(127, 1, 0, 0), cidr="10.0.0.0/16")
        addr = IPv8Address.parse("127.1.0.0.10.0.0.1")
        assert vpc.contains(addr)

    def test_not_contains(self) -> None:
        vpc = VPC(vpc_id="v1", customer="acme", zone_prefix=(127, 1, 0, 0), cidr="10.0.0.0/16")
        addr = IPv8Address.parse("127.2.0.0.10.0.0.1")
        assert not vpc.contains(addr)

    def test_to_dict(self) -> None:
        vpc = VPC(vpc_id="v1", customer="acme", zone_prefix=(127, 1, 0, 0), cidr="10.0.0.0/16")
        d = vpc.to_dict()
        assert d["vpc_id"] == "v1"
        assert d["zone_prefix"] == "127.1.0.0"

    def test_zone_prefix_str(self) -> None:
        vpc = VPC(vpc_id="v1", customer="acme", zone_prefix=(127, 5, 0, 0), cidr="10.0.0.0/16")
        assert vpc.zone_prefix_str == "127.5.0.0"


# ===================================================================
# CloudVPCFabric
# ===================================================================

class TestCloudVPCFabric:
    def test_create_vpc(self) -> None:
        fabric = CloudVPCFabric(provider_asn=64496)
        vpc = fabric.create_vpc("v1", "acme")
        assert vpc.zone_prefix == (127, 1, 0, 0)
        assert vpc.customer == "acme"

    def test_unique_zone_prefixes(self) -> None:
        fabric = CloudVPCFabric()
        v1 = fabric.create_vpc("v1", "a")
        v2 = fabric.create_vpc("v2", "b")
        v3 = fabric.create_vpc("v3", "c")
        prefixes = {v1.zone_prefix, v2.zone_prefix, v3.zone_prefix}
        assert len(prefixes) == 3

    def test_duplicate_vpc_id_raises(self) -> None:
        fabric = CloudVPCFabric()
        fabric.create_vpc("v1", "a")
        try:
            fabric.create_vpc("v1", "b")
            raise AssertionError("should fail")
        except ValueError:
            pass

    def test_get_vpc(self) -> None:
        fabric = CloudVPCFabric()
        fabric.create_vpc("v1", "a")
        assert fabric.get_vpc("v1") is not None
        assert fabric.get_vpc("v999") is None

    def test_list_vpcs(self) -> None:
        fabric = CloudVPCFabric()
        fabric.create_vpc("v1", "a")
        fabric.create_vpc("v2", "b")
        assert len(fabric.list_vpcs()) == 2

    def test_delete_vpc(self) -> None:
        fabric = CloudVPCFabric()
        fabric.create_vpc("v1", "a")
        assert fabric.delete_vpc("v1")
        assert fabric.get_vpc("v1") is None

    def test_delete_vpc_removes_peerings(self) -> None:
        fabric = CloudVPCFabric()
        fabric.create_vpc("v1", "a")
        fabric.create_vpc("v2", "b")
        fabric.create_peering("v1", "v2")
        fabric.delete_vpc("v1")
        assert len(fabric.list_peerings()) == 0

    def test_resolve_vpc(self) -> None:
        fabric = CloudVPCFabric()
        vpc = fabric.create_vpc("v1", "acme")
        addr = IPv8Address.parse(f"{vpc.zone_prefix_str}.10.0.0.1")
        assert fabric.resolve_vpc(addr) == vpc

    def test_resolve_vpc_miss(self) -> None:
        fabric = CloudVPCFabric()
        addr = IPv8Address.parse("127.99.0.0.10.0.0.1")
        assert fabric.resolve_vpc(addr) is None

    def test_can_communicate_same_vpc(self) -> None:
        fabric = CloudVPCFabric()
        vpc = fabric.create_vpc("v1", "a")
        s = IPv8Address.parse(f"{vpc.zone_prefix_str}.10.0.0.1")
        d = IPv8Address.parse(f"{vpc.zone_prefix_str}.10.0.0.2")
        assert fabric.can_communicate(s, d)

    def test_can_communicate_peered(self) -> None:
        fabric = CloudVPCFabric()
        v1 = fabric.create_vpc("v1", "a")
        v2 = fabric.create_vpc("v2", "b")
        fabric.create_peering("v1", "v2")
        s = IPv8Address.parse(f"{v1.zone_prefix_str}.10.0.0.1")
        d = IPv8Address.parse(f"{v2.zone_prefix_str}.10.0.0.1")
        assert fabric.can_communicate(s, d)

    def test_cannot_communicate_unpeered(self) -> None:
        fabric = CloudVPCFabric()
        v1 = fabric.create_vpc("v1", "a")
        v2 = fabric.create_vpc("v2", "b")
        s = IPv8Address.parse(f"{v1.zone_prefix_str}.10.0.0.1")
        d = IPv8Address.parse(f"{v2.zone_prefix_str}.10.0.0.1")
        assert not fabric.can_communicate(s, d)

    def test_create_peering_self_raises(self) -> None:
        fabric = CloudVPCFabric()
        fabric.create_vpc("v1", "a")
        try:
            fabric.create_peering("v1", "v1")
            raise AssertionError("should fail")
        except ValueError:
            pass

    def test_create_peering_unknown_raises(self) -> None:
        fabric = CloudVPCFabric()
        fabric.create_vpc("v1", "a")
        try:
            fabric.create_peering("v1", "v999")
            raise AssertionError("should fail")
        except ValueError:
            pass

    def test_duplicate_peering_idempotent(self) -> None:
        fabric = CloudVPCFabric()
        fabric.create_vpc("v1", "a")
        fabric.create_vpc("v2", "b")
        fabric.create_peering("v1", "v2")
        fabric.create_peering("v1", "v2")
        assert len(fabric.list_peerings()) == 1

    def test_validate_no_overlap(self) -> None:
        fabric = CloudVPCFabric()
        fabric.create_vpc("v1", "a")
        fabric.create_vpc("v2", "b")
        assert fabric.validate_no_overlap() == []

    def test_summary(self) -> None:
        fabric = CloudVPCFabric(provider_asn=64496)
        fabric.create_vpc("v1", "a")
        d = fabric.summary()
        assert d["provider_asn"] == 64496
        assert d["vpc_count"] == 1


# ===================================================================
# CLI tests
# ===================================================================

class TestCloudVPCCLI:
    def test_init_json(self) -> None:
        result = runner.invoke(app, ["init", "--asn", "64496", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["provider_asn"] == 64496

    def test_create_json(self) -> None:
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["create", "v1", "--customer", "acme", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["vpc_id"] == "v1"
        assert data["zone_prefix"].startswith("127.")

    def test_list_json(self) -> None:
        runner.invoke(app, ["init"])
        runner.invoke(app, ["create", "v1"])
        result = runner.invoke(app, ["list", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) >= 1

    def test_peer_json(self) -> None:
        runner.invoke(app, ["init"])
        runner.invoke(app, ["create", "v1"])
        runner.invoke(app, ["create", "v2"])
        result = runner.invoke(app, ["peer", "v1", "v2", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["vpc_a"] == "v1"

    def test_resolve_json(self) -> None:
        runner.invoke(app, ["init"])
        runner.invoke(app, ["create", "v1"])
        result = runner.invoke(app, ["resolve", "127.1.0.0.10.0.0.1", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["vpc_id"] == "v1"

    def test_check_json(self) -> None:
        runner.invoke(app, ["init"])
        runner.invoke(app, ["create", "v1"])
        result = runner.invoke(app, ["check", "127.1.0.0.10.0.0.1", "127.1.0.0.10.0.0.2", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["reachable"] is True

    def test_validate_json(self) -> None:
        runner.invoke(app, ["init"])
        runner.invoke(app, ["create", "v1"])
        result = runner.invoke(app, ["validate", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["ok"] is True

    def test_status_json(self) -> None:
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["status", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "vpc_count" in data

    def test_no_args_help(self) -> None:
        result = runner.invoke(app, [])
        assert result.exit_code in (0, 2)
