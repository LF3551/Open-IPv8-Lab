# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for ipv8lab.route."""

import pytest

from ipv8lab.address import IPv8Address
from ipv8lab.errors import NoRouteFoundError
from ipv8lab.route import Route, RouteTable, TwoTierRouteTable


@pytest.fixture
def table() -> RouteTable:
    t = RouteTable()
    t.add_route(Route("0.0.251.240", "router-a", "lab0"))
    t.add_route(Route("0.0.251.241", "router-b", "lab1"))
    t.add_route(Route("0.0.0.0", "ipv4-gateway", "ipv4"))
    return t


class TestRouteTable:
    def test_find_exact_prefix(self, table: RouteTable):
        route = table.find_route("64496-192.0.2.1")
        assert route.next_hop == "router-a"
        assert route.interface == "lab0"

    def test_find_exact_prefix_b(self, table: RouteTable):
        route = table.find_route("64497-198.51.100.7")
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
        addr = IPv8Address.parse("64496-10.0.0.1")
        route = table.find_route(addr)
        assert route.next_hop == "router-a"


# --- TwoTierRouteTable (Section 8.7) -----------------------------------------

class TestTwoTierRouteTable:
    @pytest.fixture
    def two_tier(self) -> TwoTierRouteTable:
        tt = TwoTierRouteTable()
        # Tier 1: ASN prefix routes
        tt.tier1.add_route(Route("0.0.251.240", "border-a", "wan0"))
        tt.tier1.add_route(Route("0.0.251.241", "border-b", "wan1"))
        # Tier 2: host routes (like IPv4 routing)
        tt.tier2.add_route(Route("10.0.0.0", "switch-a", "eth0"))
        tt.tier2.add_route(Route("0.0.0.0", "default-gw", "eth0"))
        return tt

    def test_tier1_asn_lookup(self, two_tier: TwoTierRouteTable):
        route = two_tier.find_route("64496-192.0.2.1")
        assert route.next_hop == "border-a"

    def test_tier1_asn_b(self, two_tier: TwoTierRouteTable):
        route = two_tier.find_route("64497-198.51.100.7")
        assert route.next_hop == "border-b"

    def test_ipv4_compatible_bypasses_tier1(self, two_tier: TwoTierRouteTable):
        """r.r.r.r = 0.0.0.0 → skip Tier 1, use Tier 2 only."""
        route = two_tier.find_route("0.0.0.0.10.0.0.1")
        assert route.next_hop == "switch-a"

    def test_ipv4_compatible_default(self, two_tier: TwoTierRouteTable):
        route = two_tier.find_route("0.0.0.0.8.8.8.8")
        assert route.next_hop == "default-gw"

    def test_tier1_fallback_to_tier2(self, two_tier: TwoTierRouteTable):
        """Unknown ASN prefix → fallback to Tier 2 default."""
        route = two_tier.find_route("0.0.251.242.10.0.0.1")
        assert route.next_hop == "switch-a"

    def test_no_route_at_all(self):
        tt = TwoTierRouteTable()
        with pytest.raises(NoRouteFoundError):
            tt.find_route("64496-192.0.2.1")

    def test_tier1_has_priority(self, two_tier: TwoTierRouteTable):
        """When Tier 1 matches, Tier 2 is not used."""
        route = two_tier.find_route("64496-10.0.0.1")
        # Tier 1 matches ASN prefix → border-a, not switch-a
        assert route.next_hop == "border-a"
