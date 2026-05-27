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
        address: 64496-192.0.2.1
        type: host

      - name: node-b
        address: 64497-198.51.100.7
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
        trace = sim.send("node-a", "64497-198.51.100.7", "hello")
        assert len(trace) >= 2
        assert any("delivered" in line for line in trace)
        assert any("hello" in line for line in trace)

    def test_packet_in_inbox(self, config_path: Path):
        sim = NetworkSimulator.load_config(config_path)
        sim.send("node-a", "64497-198.51.100.7", "test-data")
        assert len(sim.nodes["node-b"].inbox) == 1
        assert sim.nodes["node-b"].inbox[0].payload == b"test-data"


MESH_CONFIG = textwrap.dedent("""\
    network:
      name: three-asn-mesh

    nodes:
      - name: node-a
        address: 64496-10.0.1.1
        type: host
      - name: node-b
        address: 64497-10.0.2.1
        type: host
      - name: node-c
        address: 64498-10.0.3.1
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
        trace = sim.send("node-a", "64497-10.0.2.1", "mesh-ab")
        assert any("delivered" in line for line in trace)
        assert len(sim.nodes["node-b"].inbox) == 1

    def test_a_to_c(self, mesh_path: Path):
        sim = NetworkSimulator.load_config(mesh_path)
        trace = sim.send("node-a", "64498-10.0.3.1", "mesh-ac")
        assert any("delivered" in line for line in trace)
        assert len(sim.nodes["node-c"].inbox) == 1

    def test_c_to_a(self, mesh_path: Path):
        sim = NetworkSimulator.load_config(mesh_path)
        trace = sim.send("node-c", "64496-10.0.1.1", "mesh-ca")
        assert any("delivered" in line for line in trace)
        assert len(sim.nodes["node-a"].inbox) == 1

    def test_b_to_c(self, mesh_path: Path):
        sim = NetworkSimulator.load_config(mesh_path)
        trace = sim.send("node-b", "64498-10.0.3.1", "mesh-bc")
        assert any("delivered" in line for line in trace)
        assert len(sim.nodes["node-c"].inbox) == 1

    def test_three_nodes(self, mesh_path: Path):
        """All 6 nodes are loaded."""
        sim = NetworkSimulator.load_config(mesh_path)
        assert len(sim.nodes) == 6

    def test_no_loop(self, mesh_path: Path):
        """Sending to a non-existent prefix should terminate cleanly."""
        sim = NetworkSimulator.load_config(mesh_path)
        trace = sim.send("node-a", "0.0.255.255.1.1.1.1", "no-route")
        # Should end with no route or loop detected — but not infinite recursion
        assert any("no route" in line or "loop detected" in line for line in trace)


# ---------------------------------------------------------------------------
# Trace format tests — ensure hop names are never empty
# ---------------------------------------------------------------------------


class TestTraceFormat:
    """Verify trace lines always contain source and destination names."""

    def test_trace_hops_have_names(self, config_path: Path):
        """Every hop line must have non-empty source -> destination."""
        sim = NetworkSimulator.load_config(config_path)
        trace = sim.send("node-a", "64497-198.51.100.7", "hello")
        hop_lines = [line for line in trace if " -> " in line]
        assert len(hop_lines) >= 2
        for line in hop_lines:
            parts = line.split(" -> ", 1)
            src_name = parts[0].strip()
            dst_part = parts[1].strip()
            assert src_name != "", f"Empty source in trace line: {line!r}"
            assert dst_part != "", f"Empty destination in trace line: {line!r}"

    def test_trace_no_brackets(self, config_path: Path):
        """Trace lines must not use bracket notation that Rich eats."""
        sim = NetworkSimulator.load_config(config_path)
        trace = sim.send("node-a", "64497-198.51.100.7", "hello")
        for line in trace:
            if line.startswith("delivered:"):
                continue
            assert "[" not in line, f"Bracket in trace line: {line!r}"
            assert "]" not in line, f"Bracket in trace line: {line!r}"

    def test_trace_hop_order(self, config_path: Path):
        """Trace should show node-a -> router-a -> router-b -> node-b."""
        sim = NetworkSimulator.load_config(config_path)
        trace = sim.send("node-a", "64497-198.51.100.7", "hello")
        hop_lines = [line for line in trace if " -> " in line]
        assert "node-a" in hop_lines[0]
        assert "router-a" in hop_lines[0]
        assert "router-a" in hop_lines[1]
        assert "router-b" in hop_lines[1]
        assert "router-b" in hop_lines[2]
        assert "node-b" in hop_lines[2]

    def test_trace_delivered_contains_target(self, config_path: Path):
        """Delivery line must contain destination node name."""
        sim = NetworkSimulator.load_config(config_path)
        trace = sim.send("node-a", "64497-198.51.100.7", "hello")
        delivered = [line for line in trace if line.startswith("delivered:")]
        assert len(delivered) == 1
        assert "node-b" in delivered[0]
        assert "hello" in delivered[0]

    def test_trace_mesh_hops_have_names(self, mesh_path: Path):
        """Mesh topology traces also have proper hop names."""
        sim = NetworkSimulator.load_config(mesh_path)
        trace = sim.send("node-a", "64497-10.0.2.1", "mesh-test")
        hop_lines = [line for line in trace if " -> " in line]
        assert len(hop_lines) >= 2
        for line in hop_lines:
            parts = line.split(" -> ", 1)
            assert parts[0].strip() != ""
            assert parts[1].strip() != ""

    def test_trace_via_includes_interface(self, config_path: Path):
        """Route-based hops must include 'via <interface>'."""
        sim = NetworkSimulator.load_config(config_path)
        trace = sim.send("node-a", "64497-198.51.100.7", "hello")
        via_lines = [line for line in trace if "via " in line]
        assert len(via_lines) >= 1
        for line in via_lines:
            assert "via" in line
            # interface name after 'via' must not be empty
            via_idx = line.index("via ")
            interface = line[via_idx + 4:].strip()
            assert interface != ""

    def test_trace_link_hops_labeled(self, config_path: Path):
        """Link-forwarded hops must be marked with (link)."""
        sim = NetworkSimulator.load_config(config_path)
        trace = sim.send("node-a", "64497-198.51.100.7", "hello")
        link_lines = [line for line in trace if "(link)" in line]
        assert len(link_lines) >= 1
        for line in link_lines:
            parts = line.split(" -> ", 1)
            assert parts[0].strip() != ""
            assert "(link)" in parts[1]
