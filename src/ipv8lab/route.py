# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Route table and lookup logic for IPv8 Lab routing simulator."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

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
