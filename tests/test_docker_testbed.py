# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for Docker testbed module."""

from __future__ import annotations

import os
import tempfile

import yaml

from ipv8lab.docker_testbed import (
    LinkSpec,
    NodeRole,
    NodeSpec,
    Testbed,
    TestbedStats,
    build_mesh_topology,
    build_star_topology,
    build_two_asn_topology,
    generate_dockerfile,
)


# ---------------------------------------------------------------------------
# NodeSpec
# ---------------------------------------------------------------------------


class TestNodeSpec:
    def test_create(self) -> None:
        n = NodeSpec(name="r1", address="64496-10.0.1.1", role=NodeRole.ROUTER)
        assert n.name == "r1"
        assert n.role == NodeRole.ROUTER

    def test_to_dict(self) -> None:
        n = NodeSpec(name="h1", address="64496-10.0.1.10", role=NodeRole.HOST, gateway="r1")
        d = n.to_dict()
        assert d["name"] == "h1"
        assert d["role"] == "host"
        assert d["gateway"] == "r1"

    def test_default_role(self) -> None:
        n = NodeSpec(name="x", address="64496-10.0.1.1")
        assert n.role == NodeRole.HOST

    def test_services_and_env(self) -> None:
        n = NodeSpec(
            name="collector", address="64496-10.0.1.99",
            role=NodeRole.COLLECTOR,
            services=["netflow8"],
            environment={"LOG_LEVEL": "debug"},
        )
        assert "netflow8" in n.services
        assert n.environment["LOG_LEVEL"] == "debug"


# ---------------------------------------------------------------------------
# LinkSpec
# ---------------------------------------------------------------------------


class TestLinkSpec:
    def test_create(self) -> None:
        lk = LinkSpec(node_a="r1", node_b="h1", network="10.0.1.0/24")
        assert lk.network_name == "net-r1-h1"

    def test_custom_name(self) -> None:
        lk = LinkSpec(node_a="r1", node_b="r2", network="172.16.0.0/30", network_name="backbone")
        assert lk.network_name == "backbone"

    def test_to_dict(self) -> None:
        lk = LinkSpec(node_a="r1", node_b="h1", network="10.0.1.0/24")
        d = lk.to_dict()
        assert d["node_a"] == "r1"
        assert d["network"] == "10.0.1.0/24"


# ---------------------------------------------------------------------------
# Dockerfile generation
# ---------------------------------------------------------------------------


class TestDockerfile:
    def test_default(self) -> None:
        df = generate_dockerfile()
        assert "python:3.11-slim" in df
        assert "ENTRYPOINT" in df
        assert "ipv8lab" in df

    def test_custom_base(self) -> None:
        df = generate_dockerfile(base_image="python:3.12-alpine")
        assert "python:3.12-alpine" in df
        assert "python:3.11-slim" not in df


# ---------------------------------------------------------------------------
# Preset topologies
# ---------------------------------------------------------------------------


class TestPresets:
    def test_two_asn(self) -> None:
        nodes, links = build_two_asn_topology()
        assert len(nodes) == 6  # 2 routers + 2*2 hosts
        assert len(links) == 5  # 1 backbone + 4 lan
        routers = [n for n in nodes if n.role == NodeRole.ROUTER]
        assert len(routers) == 2

    def test_two_asn_custom_hosts(self) -> None:
        nodes, links = build_two_asn_topology(hosts_per_asn=3)
        assert len(nodes) == 8  # 2 + 3*2
        assert len(links) == 7  # 1 + 3*2

    def test_star(self) -> None:
        nodes, links = build_star_topology(spoke_count=5)
        assert len(nodes) == 6  # 1 core + 5 spokes
        assert len(links) == 5
        routers = [n for n in nodes if n.role == NodeRole.ROUTER]
        assert len(routers) == 1

    def test_mesh(self) -> None:
        nodes, links = build_mesh_topology(node_count=4)
        assert len(nodes) == 4
        # Full mesh: n*(n-1)/2 = 6
        assert len(links) == 6

    def test_mesh_3(self) -> None:
        nodes, links = build_mesh_topology(node_count=3)
        assert len(links) == 3

    def test_star_default(self) -> None:
        nodes, links = build_star_topology()
        assert len(nodes) == 5  # 1 + 4 default


# ---------------------------------------------------------------------------
# Testbed
# ---------------------------------------------------------------------------


class TestTestbed:
    def test_create(self) -> None:
        tb = Testbed(name="test")
        assert tb.name == "test"
        assert tb.node_count == 0

    def test_add_node(self) -> None:
        tb = Testbed()
        tb.add_node(NodeSpec(name="r1", address="64496-10.0.1.1", role=NodeRole.ROUTER))
        assert tb.node_count == 1

    def test_add_link(self) -> None:
        tb = Testbed()
        tb.add_node(NodeSpec(name="r1", address="64496-10.0.1.1", role=NodeRole.ROUTER))
        tb.add_node(NodeSpec(name="h1", address="64496-10.0.1.10"))
        lk = tb.add_link("r1", "h1", "10.0.1.0/24")
        assert tb.link_count == 1
        assert lk.network_name == "net-r1-h1"

    def test_load_topology(self) -> None:
        tb = Testbed()
        nodes, links = build_two_asn_topology()
        tb.load_topology(nodes, links)
        assert tb.node_count == 6
        assert tb.link_count == 5

    def test_get_node(self) -> None:
        tb = Testbed()
        tb.add_node(NodeSpec(name="r1", address="64496-10.0.1.1"))
        assert tb.get_node("r1") is not None
        assert tb.get_node("missing") is None

    def test_get_nodes_links(self) -> None:
        tb = Testbed()
        nodes, links = build_star_topology(spoke_count=2)
        tb.load_topology(nodes, links)
        assert len(tb.get_nodes()) == 3
        assert len(tb.get_links()) == 2

    def test_stats(self) -> None:
        tb = Testbed()
        nodes, links = build_two_asn_topology()
        tb.load_topology(nodes, links)
        s = tb.stats()
        assert isinstance(s, TestbedStats)
        assert s.router_count == 2
        assert s.host_count == 4

    def test_clear(self) -> None:
        tb = Testbed()
        nodes, links = build_two_asn_topology()
        tb.load_topology(nodes, links)
        tb.clear()
        assert tb.node_count == 0
        assert tb.link_count == 0

    def test_to_dict(self) -> None:
        tb = Testbed(name="test")
        tb.add_node(NodeSpec(name="r1", address="64496-10.0.1.1", role=NodeRole.ROUTER))
        d = tb.to_dict()
        assert d["name"] == "test"
        assert "stats" in d
        assert len(d["nodes"]) == 1  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Compose generation
# ---------------------------------------------------------------------------


class TestCompose:
    def test_generate_compose(self) -> None:
        tb = Testbed(name="test")
        nodes, links = build_two_asn_topology()
        tb.load_topology(nodes, links)
        compose = tb.generate_compose()
        assert compose["version"] == "3.8"
        assert len(compose["services"]) == 6  # type: ignore[arg-type]
        assert len(compose["networks"]) >= 1  # type: ignore[arg-type]

    def test_compose_service_fields(self) -> None:
        tb = Testbed(name="mytest")
        tb.add_node(NodeSpec(name="r1", address="64496-10.0.1.1", role=NodeRole.ROUTER))
        tb.add_node(NodeSpec(name="h1", address="64496-10.0.1.10", gateway="r1"))
        tb.add_link("r1", "h1", "10.0.1.0/24")
        compose = tb.generate_compose()
        svc_r1 = compose["services"]["r1"]  # type: ignore[index]
        assert svc_r1["hostname"] == "r1"
        assert svc_r1["environment"]["IPV8_ROLE"] == "router"
        assert "NET_ADMIN" in svc_r1["cap_add"]

    def test_compose_yaml(self) -> None:
        tb = Testbed()
        tb.add_node(NodeSpec(name="r1", address="64496-10.0.1.1", role=NodeRole.ROUTER))
        yml = tb.generate_compose_yaml()
        assert "services:" in yml
        assert "r1:" in yml

    def test_node_networks(self) -> None:
        tb = Testbed()
        tb.add_node(NodeSpec(name="r1", address="64496-10.0.1.1", role=NodeRole.ROUTER))
        tb.add_node(NodeSpec(name="h1", address="64496-10.0.1.10"))
        tb.add_link("r1", "h1", "10.0.1.0/24", network_name="lan1")
        compose = tb.generate_compose()
        svc_r1 = compose["services"]["r1"]  # type: ignore[index]
        assert "lan1" in svc_r1["networks"]

    def test_gateway_env(self) -> None:
        tb = Testbed()
        tb.add_node(NodeSpec(name="r1", address="64496-10.0.1.1", role=NodeRole.ROUTER))
        tb.add_node(NodeSpec(name="h1", address="64496-10.0.1.10", gateway="r1"))
        compose = tb.generate_compose()
        svc_h1 = compose["services"]["h1"]  # type: ignore[index]
        assert svc_h1["environment"]["IPV8_GATEWAY"] == "r1"


# ---------------------------------------------------------------------------
# Node config generation
# ---------------------------------------------------------------------------


class TestNodeConfig:
    def test_generate_config(self) -> None:
        tb = Testbed()
        tb.add_node(NodeSpec(name="r1", address="64496-10.0.1.1", role=NodeRole.ROUTER))
        tb.add_node(NodeSpec(name="h1", address="64496-10.0.1.10", gateway="r1"))
        tb.add_link("r1", "h1", "10.0.1.0/24")
        cfg = tb.generate_node_config("r1")
        assert cfg["name"] == "r1"
        assert cfg["role"] == "router"
        assert "h1" in cfg["peers"]  # type: ignore[operator]

    def test_config_unknown_node(self) -> None:
        tb = Testbed()
        try:
            tb.generate_node_config("missing")
            assert False, "Should raise"
        except ValueError:
            pass


# ---------------------------------------------------------------------------
# File output
# ---------------------------------------------------------------------------


class TestWriteOutput:
    def test_write_output(self) -> None:
        tb = Testbed(name="out-test")
        nodes, links = build_star_topology(spoke_count=2)
        tb.load_topology(nodes, links)

        with tempfile.TemporaryDirectory() as tmpdir:
            created = tb.write_output(tmpdir)
            # Dockerfile + docker-compose.yml + 3 configs
            assert len(created) == 5
            # Verify files exist
            assert os.path.isfile(os.path.join(tmpdir, "Dockerfile"))
            assert os.path.isfile(os.path.join(tmpdir, "docker-compose.yml"))
            # Parse compose
            with open(os.path.join(tmpdir, "docker-compose.yml")) as f:
                compose = yaml.safe_load(f)
            assert len(compose["services"]) == 3

    def test_configs_are_valid_yaml(self) -> None:
        tb = Testbed(name="yaml-test")
        tb.add_node(NodeSpec(name="r1", address="64496-10.0.1.1", role=NodeRole.ROUTER))
        tb.add_node(NodeSpec(name="h1", address="64496-10.0.1.10", gateway="r1"))
        tb.add_link("r1", "h1", "10.0.1.0/24")

        with tempfile.TemporaryDirectory() as tmpdir:
            tb.write_output(tmpdir)
            cfg_path = os.path.join(tmpdir, "configs", "h1.yaml")
            with open(cfg_path) as f:
                cfg = yaml.safe_load(f)
            assert cfg["name"] == "h1"
            assert cfg["gateway"] == "r1"
            assert "r1" in cfg["peers"]
