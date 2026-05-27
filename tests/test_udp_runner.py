# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for ipv8lab.udp_runner — UDP network demo."""

import textwrap
from pathlib import Path

import pytest

from ipv8lab.udp_runner import UDPNetwork

DEMO_CONFIG = textwrap.dedent("""\
    network:
      name: udp-test

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
    p = tmp_path / "udp_demo.yaml"
    p.write_text(DEMO_CONFIG)
    return p


class TestUDPNetwork:
    @pytest.mark.asyncio
    async def test_full_udp_flow(self, config_path: Path):
        net = UDPNetwork.from_yaml(config_path)
        await net.start_all()
        try:
            trace = await net.send_and_wait(
                "node-a", "64497-198.51.100.7", "udp-hello", wait=0.5
            )
            assert any("Sending" in line for line in trace)
            assert any("Received" in line and "udp-hello" in line for line in trace)
            assert len(net.nodes["node-b"].node.inbox) == 1
            assert net.nodes["node-b"].node.inbox[0].payload == b"udp-hello"
        finally:
            net.stop_all()
