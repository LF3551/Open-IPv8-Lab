# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for the web dashboard."""

from __future__ import annotations

import json
import threading
from http.server import HTTPServer
from pathlib import Path

import pytest

from ipv8lab.dashboard import _topology_json, make_handler
from ipv8lab.simulator import NetworkSimulator

try:
    from urllib.request import Request, urlopen
except ImportError:
    pass


@pytest.fixture()
def sim(tmp_path: Path) -> NetworkSimulator:
    cfg = tmp_path / "net.yaml"
    cfg.write_text(
        """network:
  name: dashboard-test

nodes:
  - name: node-a
    address: "1.0.0.0.10.0.0.1"
  - name: node-b
    address: "2.0.0.0.10.0.0.2"

links:
  - from: node-a
    to: node-b
"""
    )
    return NetworkSimulator.load_config(cfg)


class TestTopologyJson:
    def test_node_count(self, sim: NetworkSimulator) -> None:
        data = _topology_json(sim)
        assert len(data["nodes"]) == 2

    def test_node_fields(self, sim: NetworkSimulator) -> None:
        data = _topology_json(sim)
        node = data["nodes"][0]
        assert "name" in node
        assert "address" in node
        assert "route_count" in node
        assert "inbox_count" in node

    def test_links(self, sim: NetworkSimulator) -> None:
        data = _topology_json(sim)
        assert len(data["links"]) == 1


class TestDashboardServer:
    @pytest.fixture()
    def server_url(self, sim: NetworkSimulator) -> str:
        handler = make_handler(sim)
        srv = HTTPServer(("127.0.0.1", 0), handler)
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        yield f"http://127.0.0.1:{port}"
        srv.shutdown()

    def test_index(self, server_url: str) -> None:
        with urlopen(f"{server_url}/") as resp:
            body = resp.read().decode()
            assert "IPv8 Lab Dashboard" in body

    def test_api_topology(self, server_url: str) -> None:
        with urlopen(f"{server_url}/api/topology") as resp:
            data = json.loads(resp.read())
            assert len(data["nodes"]) == 2

    def test_api_send(self, server_url: str) -> None:
        req = Request(
            f"{server_url}/api/send",
            data=json.dumps(
                {"src": "node-a", "dst": "2.0.0.0.10.0.0.2", "payload": "test"}
            ).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(req) as resp:
            data = json.loads(resp.read())
            assert "trace" in data
            assert len(data["trace"]) > 0

    def test_404(self, server_url: str) -> None:
        from urllib.error import HTTPError

        with pytest.raises(HTTPError, match="404"):
            urlopen(f"{server_url}/nonexistent")
