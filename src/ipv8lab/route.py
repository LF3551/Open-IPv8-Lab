# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Route table and lookup logic for IPv8 Lab routing simulator."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from ipv8lab.address import IPv8Address
from ipv8lab.errors import NoRouteFoundError


@dataclass(frozen=True, slots=True)
class Route:
    """A single route entry."""

    destination_prefix: str
    next_hop: str
    interface: str


@dataclass(slots=True)
class RouteTable:
    """Collection of routes with prefix-based lookup."""

    routes: list[Route] = field(default_factory=list)

    def add_route(self, route: Route) -> None:
        self.routes.append(route)

    def remove_route(self, destination_prefix: str) -> bool:
        before = len(self.routes)
        self.routes = [r for r in self.routes if r.destination_prefix != destination_prefix]
        return len(self.routes) < before

    def find_route(self, address: str | IPv8Address) -> Route:
        """Find the best matching route for *address*.

        Returns the matching ``Route`` or raises ``NoRouteFoundError``.
        """
        if isinstance(address, str):
            address = IPv8Address.parse(address)

        prefix_str = address.prefix_str

        # exact prefix match first
        for route in self.routes:
            if route.destination_prefix == prefix_str:
                return route

        # fallback: default route 0.0.0.0
        for route in self.routes:
            if route.destination_prefix == "0.0.0.0":
                return route

        raise NoRouteFoundError(f"No route found for prefix {prefix_str}")

    @classmethod
    def load_from_yaml(cls, path: str | Path) -> "RouteTable":
        """Load routes from a YAML file.

        Expected format::

            routes:
              - destination_prefix: "0.0.251.240"
                next_hop: "router-a"
                interface: "lab0"
        """
        with open(path) as fh:
            data = yaml.safe_load(fh)
        table = cls()
        for entry in data.get("routes", []):
            table.add_route(
                Route(
                    destination_prefix=str(entry["destination_prefix"]),
                    next_hop=str(entry["next_hop"]),
                    interface=str(entry["interface"]),
                )
            )
        return table


@dataclass(slots=True)
class TwoTierRouteTable:
    """Two-tier routing table per Section 8.7.

    Tier 1 (global): routes by r.r.r.r routing prefix → AS border router.
    Tier 2 (local):  routes by n.n.n.n host address  → same as IPv4 routing.

    When r.r.r.r = 0.0.0.0 (IPv4-compatible), Tier 1 is bypassed.
    """

    tier1: RouteTable = field(default_factory=RouteTable)
    tier2: RouteTable = field(default_factory=RouteTable)

    def find_route(self, address: str | IPv8Address) -> Route:
        """Look up the best route using two-tier logic."""
        if isinstance(address, str):
            address = IPv8Address.parse(address)

        # When r.r.r.r = 0.0.0.0, bypass Tier 1 — route on n.n.n.n only
        if address.is_ipv4_compatible():
            return self._tier2_lookup(address)

        # Tier 1: route by ASN prefix
        try:
            return self.tier1.find_route(address)
        except NoRouteFoundError:
            pass

        # Fallback to Tier 2
        return self._tier2_lookup(address)

    def _tier2_lookup(self, address: IPv8Address) -> Route:
        """Tier 2 lookup by host part (n.n.n.n)."""
        host_str = address.host_str

        # Exact host match
        for route in self.tier2.routes:
            if route.destination_prefix == host_str:
                return route

        # Prefix match: compare by first octets (simple /8, /16, /24 matching)
        host_parts = host_str.split(".")
        for prefix_len in (3, 2, 1):
            candidate = ".".join(host_parts[:prefix_len]) + ".0" * (4 - prefix_len)
            for route in self.tier2.routes:
                if route.destination_prefix == candidate:
                    return route

        # Fallback: default route
        for route in self.tier2.routes:
            if route.destination_prefix == "0.0.0.0":
                return route

        raise NoRouteFoundError(
            f"No route found for {address.canonical} "
            f"(prefix={address.prefix_str}, host={host_str})"
        )
