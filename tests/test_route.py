# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for ipv8lab.route."""

import pytest

from ipv8lab.address import IPv8Address
from ipv8lab.errors import NoRouteFoundError
from ipv8lab.route import Route, RouteTable


@pytest.fixture
def table() -> RouteTable:
    t = RouteTable()
    t.add_route(Route("0.0.251.240", "router-a", "lab0"))
    t.add_route(Route("0.0.251.241", "router-b", "lab1"))
    t.add_route(Route("0.0.0.0", "ipv4-gateway", "ipv4"))
    return t


class TestRouteTable:
    def test_find_exact_prefix(self, table: RouteTable):
        route = table.find_route("64496.192.0.2.1")
        assert route.next_hop == "router-a"
        assert route.interface == "lab0"

    def test_find_exact_prefix_b(self, table: RouteTable):
        route = table.find_route("64497.198.51.100.7")
        assert route.next_hop == "router-b"

    def test_fallback_default_route(self, table: RouteTable):
        route = table.find_route("0.0.0.0.8.8.8.8")
        assert route.next_hop == "ipv4-gateway"

    def test_no_route(self):
        t = RouteTable()
        t.add_route(Route("0.0.251.240", "router-a", "lab0"))
        with pytest.raises(NoRouteFoundError):
            t.find_route("0.0.251.241.1.1.1.1")

    def test_remove_route(self, table: RouteTable):
        assert table.remove_route("0.0.251.240")
        assert not table.remove_route("nonexistent")

    def test_find_with_address_object(self, table: RouteTable):
        addr = IPv8Address.parse("64496.10.0.0.1")
        route = table.find_route(addr)
        assert route.next_hop == "router-a"
