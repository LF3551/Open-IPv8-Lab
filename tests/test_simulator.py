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
