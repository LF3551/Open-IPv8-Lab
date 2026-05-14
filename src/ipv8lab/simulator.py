# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Network simulator — loads a YAML config and traces packets between nodes."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

from ipv8lab.address import IPv8Address
from ipv8lab.errors import NoRouteFoundError
from ipv8lab.node import Node
from ipv8lab.packet import IPv8Packet, PROTO_EXPERIMENTAL
from ipv8lab.route import Route, RouteTable


@dataclass(slots=True)
class NetworkSimulator:
    """In-memory simulation of an IPv8 Lab network."""

    name: str = "unnamed"
    nodes: dict[str, Node] = field(default_factory=dict)
    links: list[tuple[str, str]] = field(default_factory=list)
    trace: list[str] = field(default_factory=list)

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
        src_node = self.nodes[src_name]
        dst_addr = IPv8Address.parse(dst_address)
        pkt = IPv8Packet(
            src=src_node.address,
            dst=dst_addr,
            payload=payload.encode(),
        )
        src_node.send_packet(pkt)
        self.trace.append(f"[{src_node.name}] Sending packet to {dst_addr.full_notation}")
        self._forward(src_node.name, pkt)
        return list(self.trace)

    def _forward(self, current_name: str, pkt: IPv8Packet) -> None:
        """Recursively forward the packet through the network."""
        # Check if destination is this node
        for name, node in self.nodes.items():
            if node.address.to_int() == pkt.dst.to_int():
                if name == current_name:
                    node.receive_packet(pkt)
                    self.trace.append(
                        f"[{name}] Packet delivered. Payload: {pkt.payload.decode(errors='replace')}"
                    )
                    return

        current_node = self.nodes[current_name]

        # Try to find a route
        try:
            route = current_node.routes.find_route(pkt.dst)
        except NoRouteFoundError:
            # No explicit route — try forwarding via linked nodes
            for frm, to in self.links:
                if frm == current_name and to in self.nodes:
                    next_node = self.nodes[to]
                    # Check if the next node IS the destination
                    if next_node.address.to_int() == pkt.dst.to_int():
                        self.trace.append(f"[{current_name}] -> [{to}]")
                        next_node.receive_packet(pkt)
                        self.trace.append(
                            f"[{to}] Packet delivered. "
                            f"Payload: {pkt.payload.decode(errors='replace')}"
                        )
                        return
                    # Otherwise forward to the linked node and let it route
                    self.trace.append(f"[{current_name}] -> [{to}] (link)")
                    pkt.ttl -= 1
                    if pkt.ttl <= 0:
                        self.trace.append(f"[{to}] TTL expired, packet dropped")
                        return
                    self._forward(to, pkt)
                    return
            self.trace.append(f"[{current_name}] No route to {pkt.dst.full_notation}")
            return

        next_hop = route.next_hop
        self.trace.append(f"[{current_name}] -> [{next_hop}] via {route.interface}")

        if next_hop not in self.nodes:
            self.trace.append(f"[{next_hop}] Node not found in simulation")
            return

        pkt.ttl -= 1
        if pkt.ttl <= 0:
            self.trace.append(f"[{next_hop}] TTL expired, packet dropped")
            return

        # Check if next_hop is the destination
        if self.nodes[next_hop].address.to_int() == pkt.dst.to_int():
            self.nodes[next_hop].receive_packet(pkt)
            self.trace.append(
                f"[{next_hop}] Packet delivered. "
                f"Payload: {pkt.payload.decode(errors='replace')}"
            )
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
