# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""UDP node runner — launches IPv8 Lab nodes as independent async tasks
communicating over real UDP sockets.

Each node binds to a local UDP port and can send/receive IPv8 Lab packets.
A router node additionally performs prefix-based forwarding.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from ipv8lab.address import IPv8Address
from ipv8lab.node import Node
from ipv8lab.packet import IPv8Packet
from ipv8lab.route import Route
from ipv8lab.transport import UDPEndpoint, UDPTransport

log = logging.getLogger(__name__)


@dataclass(slots=True)
class UDPNode:
    """A network node with a real UDP transport."""

    node: Node
    endpoint: UDPEndpoint
    transport: UDPTransport | None = field(default=None, init=False)
    peer_map: dict[str, UDPEndpoint] = field(default_factory=dict)
    _peer_addresses: dict[str, int] = field(default_factory=dict)
    is_router: bool = False
    trace: list[str] = field(default_factory=list)

    def _on_packet(self, pkt: IPv8Packet, addr: tuple[str, int]) -> None:
        # Is this packet for us?
        if pkt.dst.to_int() == self.node.address.to_int():
            self.node.receive_packet(pkt)
            msg = (
                f"[{self.node.name}] Received packet from {pkt.src.canonical}: "
                f"{pkt.payload.decode(errors='replace')}"
            )
            log.info(msg)
            self.trace.append(msg)
            return

        # Router forwarding logic
        if self.is_router:
            pkt.ttl -= 1
            if pkt.ttl <= 0:
                msg = f"[{self.node.name}] TTL expired, dropping packet"
                log.warning(msg)
                self.trace.append(msg)
                return

            # First try route table
            next_hop: str | None = None
            try:
                route = self.node.routes.find_route(pkt.dst)
                next_hop = route.next_hop
            except Exception:
                pass

            # If no route, check if any peer IS the destination (direct delivery)
            if next_hop is None:
                for peer_name, peer_addr_int in self._peer_addresses.items():
                    if peer_addr_int == pkt.dst.to_int():
                        next_hop = peer_name
                        break

            if next_hop is None:
                msg = f"[{self.node.name}] No route to {pkt.dst.canonical}"
                log.warning(msg)
                self.trace.append(msg)
                return

            if next_hop not in self.peer_map:
                msg = f"[{self.node.name}] Peer {next_hop} not in peer map"
                log.warning(msg)
                self.trace.append(msg)
                return

            remote = self.peer_map[next_hop]
            msg = f"[{self.node.name}] Forwarding to {next_hop} ({remote.host}:{remote.port})"
            log.info(msg)
            self.trace.append(msg)
            if self.transport:
                self.transport.send(pkt, remote)

    async def start(self) -> None:
        self.transport = UDPTransport(self.endpoint, on_packet=self._on_packet)
        await self.transport.start()
        # update endpoint with actual port
        self.endpoint = self.transport.local

    def send_to(self, pkt: IPv8Packet, peer_name: str) -> None:
        if peer_name not in self.peer_map:
            raise ValueError(f"Unknown peer: {peer_name}")
        if self.transport is None:
            raise RuntimeError("Transport not started")
        remote = self.peer_map[peer_name]
        msg = f"[{self.node.name}] Sending to {peer_name} ({remote.host}:{remote.port})"
        log.info(msg)
        self.trace.append(msg)
        self.transport.send(pkt, remote)

    def stop(self) -> None:
        if self.transport:
            self.transport.stop()


class UDPNetwork:
    """Manages a set of UDPNodes and wires them together for a demo."""

    def __init__(self) -> None:
        self.nodes: dict[str, UDPNode] = {}
        self.trace: list[str] = []

    async def start_all(self) -> None:
        for unode in self.nodes.values():
            await unode.start()
        # After all nodes started (ports assigned), update peer maps
        for unode in self.nodes.values():
            for peer_name, peer_node in self.nodes.items():
                if peer_name != unode.node.name:
                    unode.peer_map[peer_name] = peer_node.endpoint
                    unode._peer_addresses[peer_name] = peer_node.node.address.to_int()

    def stop_all(self) -> None:
        for unode in self.nodes.values():
            unode.stop()

    def collect_trace(self) -> list[str]:
        result: list[str] = []
        for unode in self.nodes.values():
            result.extend(unode.trace)
        return result

    async def send_and_wait(
        self,
        src_name: str,
        dst_address: str,
        payload: str,
        wait: float = 0.3,
    ) -> list[str]:
        """Send a packet and wait briefly for it to propagate."""
        src_unode = self.nodes[src_name]
        src_node = src_unode.node
        dst_addr = IPv8Address.parse(dst_address)

        pkt = IPv8Packet(src=src_node.address, dst=dst_addr, payload=payload.encode())

        # Find first linked peer (typically a router)
        first_hop: str | None = None
        try:
            route = src_node.routes.find_route(dst_addr)
            first_hop = route.next_hop
        except Exception:
            # Try any linked router
            for peer_name, peer_unode in self.nodes.items():
                if peer_name != src_name and peer_unode.is_router:
                    first_hop = peer_name
                    break

        if first_hop is None:
            return [f"[{src_name}] No route to {dst_addr.canonical}"]

        src_unode.send_to(pkt, first_hop)
        await asyncio.sleep(wait)

        return self.collect_trace()

    @classmethod
    def from_yaml(cls, path: str | Path) -> "UDPNetwork":
        """Load a UDP network from the same YAML config format as the simulator."""
        with open(path) as fh:
            data = yaml.safe_load(fh)

        net = cls()

        # Create host nodes — port 0 means OS picks
        for node_cfg in data.get("nodes", []):
            addr = IPv8Address.parse(node_cfg["address"])
            node = Node(name=node_cfg["name"], address=addr)
            unode = UDPNode(
                node=node,
                endpoint=UDPEndpoint(port=0),
                is_router=False,
            )
            net.nodes[node_cfg["name"]] = unode

        # Create routers
        for router_cfg in data.get("routers", []):
            asn = router_cfg["asn"]
            addr = IPv8Address.parse(f"{asn}.0.0.0.1")
            node = Node(name=router_cfg["name"], address=addr)
            unode = UDPNode(
                node=node,
                endpoint=UDPEndpoint(port=0),
                is_router=True,
            )
            net.nodes[router_cfg["name"]] = unode

        # Add routes
        for route_cfg in data.get("routes", []):
            router_name = route_cfg["router"]
            if router_name in net.nodes:
                net.nodes[router_name].node.routes.add_route(
                    Route(
                        destination_prefix=str(route_cfg["destination_prefix"]),
                        next_hop=str(route_cfg["next_hop"]),
                        interface=str(route_cfg["interface"]),
                    )
                )

        # For host nodes, add a default route via any connected router
        for link in data.get("links", []):
            frm, to = link["from"], link["to"]
            if frm in net.nodes and to in net.nodes:
                frm_node = net.nodes[frm]
                to_node = net.nodes[to]
                if not frm_node.is_router and to_node.is_router:
                    frm_node.node.routes.add_route(
                        Route("0.0.0.0", to, "default")
                    )

        return net
