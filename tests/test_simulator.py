# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for ipv8lab.simulator."""

import textwrap
from pathlib import Path

import pytest

from ipv8lab.simulator import NetworkSimulator


DEMO_CONFIG = textwrap.dedent("""\
    network:
      name: two-asn-demo

    nodes:
      - name: node-a
        address: 64496.192.0.2.1
        type: host

      - name: node-b
        address: 64497.198.51.100.7
        type: host

    routers:
      - name: router-a
        asn: 64496

      - name: router-b
        asn: 64497

    links:
      - from: node-a
        to: router-a

      - from: router-a
        to: router-b

      - from: router-b
        to: node-b

    routes:
      - router: router-a
        destination_prefix: "0.0.251.241"
        next_hop: router-b
        interface: lab1

      - router: router-b
        destination_prefix: "0.0.251.240"
        next_hop: router-a
        interface: lab1
""")


@pytest.fixture
def config_path(tmp_path: Path) -> Path:
    p = tmp_path / "demo.yaml"
    p.write_text(DEMO_CONFIG)
    return p


class TestNetworkSimulator:
    def test_load_config(self, config_path: Path):
        sim = NetworkSimulator.load_config(config_path)
        assert sim.name == "two-asn-demo"
        assert "node-a" in sim.nodes
        assert "node-b" in sim.nodes
        assert "router-a" in sim.nodes
        assert "router-b" in sim.nodes

    def test_send_packet(self, config_path: Path):
        sim = NetworkSimulator.load_config(config_path)
        trace = sim.send("node-a", "64497.198.51.100.7", "hello")
        assert len(trace) >= 2
        assert any("Packet delivered" in line for line in trace)
        assert any("hello" in line for line in trace)

    def test_packet_in_inbox(self, config_path: Path):
        sim = NetworkSimulator.load_config(config_path)
        sim.send("node-a", "64497.198.51.100.7", "test-data")
        assert len(sim.nodes["node-b"].inbox) == 1
        assert sim.nodes["node-b"].inbox[0].payload == b"test-data"


MESH_CONFIG = textwrap.dedent("""\
    network:
      name: three-asn-mesh

    nodes:
      - name: node-a
        address: 64496.10.0.1.1
        type: host
      - name: node-b
        address: 64497.10.0.2.1
        type: host
      - name: node-c
        address: 64498.10.0.3.1
        type: host

    routers:
      - name: router-a
        asn: 64496
      - name: router-b
        asn: 64497
      - name: router-c
        asn: 64498

    links:
      - from: node-a
        to: router-a
      - from: node-b
        to: router-b
      - from: node-c
        to: router-c
      - from: router-a
        to: router-b
      - from: router-b
        to: router-a
      - from: router-a
        to: router-c
      - from: router-c
        to: router-a
      - from: router-b
        to: router-c
      - from: router-c
        to: router-b
      - from: router-a
        to: node-a
      - from: router-b
        to: node-b
      - from: router-c
        to: node-c

    routes:
      - router: router-a
        destination_prefix: "0.0.251.241"
        next_hop: router-b
        interface: mesh0
      - router: router-a
        destination_prefix: "0.0.251.242"
        next_hop: router-c
        interface: mesh1
      - router: router-b
        destination_prefix: "0.0.251.240"
        next_hop: router-a
        interface: mesh0
      - router: router-b
        destination_prefix: "0.0.251.242"
        next_hop: router-c
        interface: mesh1
      - router: router-c
        destination_prefix: "0.0.251.240"
        next_hop: router-a
        interface: mesh0
      - router: router-c
        destination_prefix: "0.0.251.241"
        next_hop: router-b
        interface: mesh1
""")


@pytest.fixture
def mesh_path(tmp_path: Path) -> Path:
    p = tmp_path / "mesh.yaml"
    p.write_text(MESH_CONFIG)
    return p


class TestMeshTopology:
    def test_a_to_b(self, mesh_path: Path):
        sim = NetworkSimulator.load_config(mesh_path)
        trace = sim.send("node-a", "64497.10.0.2.1", "mesh-ab")
        assert any("Packet delivered" in line for line in trace)
        assert len(sim.nodes["node-b"].inbox) == 1

    def test_a_to_c(self, mesh_path: Path):
        sim = NetworkSimulator.load_config(mesh_path)
        trace = sim.send("node-a", "64498.10.0.3.1", "mesh-ac")
        assert any("Packet delivered" in line for line in trace)
        assert len(sim.nodes["node-c"].inbox) == 1

    def test_c_to_a(self, mesh_path: Path):
        sim = NetworkSimulator.load_config(mesh_path)
        trace = sim.send("node-c", "64496.10.0.1.1", "mesh-ca")
        assert any("Packet delivered" in line for line in trace)
        assert len(sim.nodes["node-a"].inbox) == 1

    def test_b_to_c(self, mesh_path: Path):
        sim = NetworkSimulator.load_config(mesh_path)
        trace = sim.send("node-b", "64498.10.0.3.1", "mesh-bc")
        assert any("Packet delivered" in line for line in trace)
        assert len(sim.nodes["node-c"].inbox) == 1

    def test_three_nodes(self, mesh_path: Path):
        """All 6 nodes are loaded."""
        sim = NetworkSimulator.load_config(mesh_path)
        assert len(sim.nodes) == 6

    def test_no_loop(self, mesh_path: Path):
        """Sending to a non-existent prefix should terminate cleanly."""
        sim = NetworkSimulator.load_config(mesh_path)
        trace = sim.send("node-a", "0.0.255.255.1.1.1.1", "no-route")
        # Should end with No route or Loop detected — but not infinite recursion
        assert any("No route" in line or "Loop detected" in line for line in trace)
