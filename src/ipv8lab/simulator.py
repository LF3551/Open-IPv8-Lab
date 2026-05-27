# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Network simulator — loads a YAML config and traces packets between nodes."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from ipv8lab.address import IPv8Address
from ipv8lab.errors import NoRouteFoundError
from ipv8lab.node import Node
from ipv8lab.packet import IPv8Packet
from ipv8lab.route import Route


@dataclass(slots=True)
class NetworkSimulator:
    """In-memory simulation of an IPv8 Lab network."""

    name: str = "unnamed"
    nodes: dict[str, Node] = field(default_factory=dict)
    links: list[tuple[str, str]] = field(default_factory=list)
    trace: list[str] = field(default_factory=list)
    _visited: set[str] = field(default_factory=set)

    # --- setup ----------------------------------------------------------------

    def add_node(self, node: Node) -> None:
        self.nodes[node.name] = node

    def add_link(self, from_name: str, to_name: str) -> None:
        self.links.append((from_name, to_name))

    # --- simulation -----------------------------------------------------------

    def send(self, src_name: str, dst_address: str, payload: str) -> list[str]:
        """Simulate sending a packet from *src_name* to *dst_address*.

        Returns the trace log of hops.
        """
        self.trace.clear()
        self._visited.clear()
        src_node = self.nodes[src_name]
        dst_addr = IPv8Address.parse(dst_address)
        pkt = IPv8Packet(
            src=src_node.address,
            dst=dst_addr,
            payload=payload.encode(),
        )
        src_node.send_packet(pkt)
        self._forward(src_node.name, pkt)
        return list(self.trace)

    def _forward(self, current_name: str, pkt: IPv8Packet) -> None:
        """Recursively forward the packet through the network."""
        # Cycle detection for forwarding
        if current_name in self._visited:
            self.trace.append(f"{current_name} -> {current_name}  loop detected, packet dropped")
            return
        self._visited.add(current_name)

        # Check if destination is this node
        current_node = self.nodes[current_name]
        if current_node.address.to_int() == pkt.dst.to_int():
            self.trace.append(
                f"delivered:{current_name}:{pkt.payload.decode(errors='replace')}"
            )
            current_node.receive_packet(pkt)
            return

        # Check linked nodes for direct delivery
        for frm, to in self.links:
            if frm == current_name and to in self.nodes:
                if self.nodes[to].address.to_int() == pkt.dst.to_int():
                    self.trace.append(f"{current_name} -> {to}  (link)")
                    self.nodes[to].receive_packet(pkt)
                    self.trace.append(
                        f"delivered:{to}:{pkt.payload.decode(errors='replace')}"
                    )
                    return

        # Try to find a route
        try:
            route = current_node.routes.find_route(pkt.dst)
        except NoRouteFoundError:
            # No explicit route — try forwarding via linked nodes
            for frm, to in self.links:
                if frm == current_name and to in self.nodes and to not in self._visited:
                    self.trace.append(f"{current_name} -> {to}  (link)")
                    pkt.ttl -= 1
                    if pkt.ttl <= 0:
                        self.trace.append(f"{to} -> *  TTL expired, packet dropped")
                        return
                    self._forward(to, pkt)
                    return
            self.trace.append(f"{current_name} -> *  no route to {pkt.dst.canonical}")
            return

        next_hop = route.next_hop
        self.trace.append(f"{current_name} -> {next_hop}  via {route.interface}")

        if next_hop not in self.nodes:
            self.trace.append(f"{next_hop} -> *  node not found in simulation")
            return

        pkt.ttl -= 1
        if pkt.ttl <= 0:
            self.trace.append(f"{next_hop} -> *  TTL expired, packet dropped")
            return

        self._forward(next_hop, pkt)

    # --- config loading -------------------------------------------------------

    @classmethod
    def load_config(cls, path: str | Path) -> "NetworkSimulator":
        """Load a full network topology from a YAML config file."""
        with open(path) as fh:
            data = yaml.safe_load(fh)

        sim = cls(name=data.get("network", {}).get("name", "unnamed"))

        # Create host nodes
        for node_cfg in data.get("nodes", []):
            addr = IPv8Address.parse(node_cfg["address"])
            sim.add_node(Node(name=node_cfg["name"], address=addr))

        # Create routers (they get a synthetic address based on ASN + .0.0.0.1)
        for router_cfg in data.get("routers", []):
            asn = router_cfg["asn"]
            addr = IPv8Address.parse(f"{asn}.0.0.0.1")
            node = Node(name=router_cfg["name"], address=addr)
            sim.add_node(node)

        # Create links
        for link in data.get("links", []):
            sim.add_link(link["from"], link["to"])

        # Add routes
        for route_cfg in data.get("routes", []):
            router_name = route_cfg["router"]
            if router_name in sim.nodes:
                sim.nodes[router_name].routes.add_route(
                    Route(
                        destination_prefix=str(route_cfg["destination_prefix"]),
                        next_hop=str(route_cfg["next_hop"]),
                        interface=str(route_cfg["interface"]),
                    )
                )

        return sim
