# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Traceroute8 — IPv8 traceroute diagnostic utility.

Simulates traceroute over an IPv8 network topology by sending probe packets
with incrementing TTL values.  Each simulated router along the path decrements
TTL and, when it reaches zero, returns an ICMPv8 Time Exceeded message.

The simulation is entirely in-process — no real sockets are used.  The caller
builds a ``Topology`` describing routers and links, then ``traceroute()``
walks the path hop-by-hop.

Key concepts:

* **Topology** — a directed graph of routers.  Each router has an IPv8 address
  and a routing table mapping destination prefixes to next-hop router names.
* **Hop** — one step in the path; records the responding router address, the
  probe TTL, and the simulated round-trip time.
* **TracerouteResult** — ordered list of hops from source to destination (or
  to the point where the path ends / loops).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from ipv8lab.address import IPv8Address
from ipv8lab.icmpv8 import (
    ICMPv8Type,
)


# ---------------------------------------------------------------------------
# Topology
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Router:
    """A simulated router in the topology."""

    name: str
    address: IPv8Address
    routes: dict[str, str] = field(default_factory=dict)
    # routes: destination_prefix → next_hop_router_name
    # special key "*" = default route

    def lookup(self, dst: IPv8Address) -> str | None:
        """Return next-hop router name for *dst*, or ``None``."""
        prefix = dst.prefix_str
        if prefix in self.routes:
            return self.routes[prefix]
        return self.routes.get("*")


@dataclass(slots=True)
class Topology:
    """A network topology for traceroute simulation."""

    routers: dict[str, Router] = field(default_factory=dict)

    def add_router(
        self,
        name: str,
        address: str | IPv8Address,
        routes: dict[str, str] | None = None,
    ) -> Router:
        """Add a router to the topology."""
        if isinstance(address, str):
            address = IPv8Address.parse(address)
        r = Router(name=name, address=address, routes=routes or {})
        self.routers[name] = r
        return r

    def get_router(self, name: str) -> Router | None:
        return self.routers.get(name)

    @property
    def router_count(self) -> int:
        return len(self.routers)


# ---------------------------------------------------------------------------
# Hop / Result
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Hop:
    """One hop in a traceroute result."""

    ttl: int
    address: IPv8Address
    router_name: str
    rtt_ms: float
    icmp_type: ICMPv8Type
    reached: bool = False  # True only for the final destination hop


@dataclass(slots=True)
class TracerouteResult:
    """Result of a traceroute run."""

    src: IPv8Address
    dst: IPv8Address
    hops: list[Hop] = field(default_factory=list)
    completed: bool = False  # True if destination was reached
    error: str | None = None

    @property
    def hop_count(self) -> int:
        return len(self.hops)

    def path_addresses(self) -> list[str]:
        """Return list of hop addresses as strings."""
        return [str(h.address) for h in self.hops]

    def to_dict(self) -> dict[str, object]:
        return {
            "src": str(self.src),
            "dst": str(self.dst),
            "completed": self.completed,
            "hop_count": self.hop_count,
            "error": self.error,
            "hops": [
                {
                    "ttl": h.ttl,
                    "address": str(h.address),
                    "router": h.router_name,
                    "rtt_ms": h.rtt_ms,
                    "icmp_type": h.icmp_type.name,
                    "reached": h.reached,
                }
                for h in self.hops
            ],
        }


# ---------------------------------------------------------------------------
# Simulated RTT
# ---------------------------------------------------------------------------


def _simulated_rtt(router_name: str, ttl: int) -> float:
    """Deterministic simulated RTT based on router name + ttl.

    Produces a stable, reproducible value in [0.5, 15.0] ms.
    """
    h = hashlib.md5(f"{router_name}:{ttl}".encode(), usedforsecurity=False)
    raw = int.from_bytes(h.digest()[:2], "big")
    return round(0.5 + (raw / 65535) * 14.5, 2)


# ---------------------------------------------------------------------------
# Traceroute engine
# ---------------------------------------------------------------------------

DEFAULT_MAX_HOPS = 30
DEFAULT_PROBES = 1  # probes per TTL (we record one hop per TTL)


def traceroute(
    topology: Topology,
    src: str | IPv8Address,
    dst: str | IPv8Address,
    *,
    max_hops: int = DEFAULT_MAX_HOPS,
    start_ttl: int = 1,
) -> TracerouteResult:
    """Run a simulated traceroute from *src* to *dst* over *topology*.

    The source address is used to find the first router (must exist in the
    topology or be directly connected to one).
    """
    if isinstance(src, str):
        src = IPv8Address.parse(src)
    if isinstance(dst, str):
        dst = IPv8Address.parse(dst)

    result = TracerouteResult(src=src, dst=dst)

    # Find starting router — look for a router whose address matches src's prefix
    start_router = _find_router_for(topology, src)
    if start_router is None:
        result.error = f"No router found for source {src}"
        return result

    for ttl in range(start_ttl, start_ttl + max_hops):
        # Walk the path TTL hops from the start
        current_name: str | None = start_router.name
        hops_walked = 0

        visited: set[str] = set()

        while current_name is not None and hops_walked < ttl:
            if current_name in visited:
                result.error = f"Routing loop detected at {current_name}"
                return result
            visited.add(current_name)

            router = topology.get_router(current_name)
            if router is None:
                result.error = f"Router {current_name} not in topology"
                return result

            # Check if this router IS the destination
            if router.address == dst:
                rtt = _simulated_rtt(router.name, ttl)
                result.hops.append(Hop(
                    ttl=ttl, address=router.address,
                    router_name=router.name, rtt_ms=rtt,
                    icmp_type=ICMPv8Type.ECHO_REPLY, reached=True,
                ))
                result.completed = True
                return result

            next_name = router.lookup(dst)
            if next_name is None:
                # No route — destination unreachable at this router
                rtt = _simulated_rtt(router.name, ttl)
                result.hops.append(Hop(
                    ttl=ttl, address=router.address,
                    router_name=router.name, rtt_ms=rtt,
                    icmp_type=ICMPv8Type.DESTINATION_UNREACHABLE,
                ))
                result.error = f"No route at {router.name} for {dst}"
                return result

            current_name = next_name
            hops_walked += 1

        # After walking TTL hops, the current router decrements TTL to 0
        if current_name is not None:
            router = topology.get_router(current_name)
            if router is None:
                result.error = f"Router {current_name} not in topology"
                return result

            # Check if we arrived at destination exactly at this TTL
            if router.address == dst:
                rtt = _simulated_rtt(router.name, ttl)
                result.hops.append(Hop(
                    ttl=ttl, address=router.address,
                    router_name=router.name, rtt_ms=rtt,
                    icmp_type=ICMPv8Type.ECHO_REPLY, reached=True,
                ))
                result.completed = True
                return result

            # TTL expired at this router → Time Exceeded
            rtt = _simulated_rtt(router.name, ttl)
            result.hops.append(Hop(
                ttl=ttl, address=router.address,
                router_name=router.name, rtt_ms=rtt,
                icmp_type=ICMPv8Type.TIME_EXCEEDED,
            ))

    if not result.completed:
        result.error = f"Destination not reached within {max_hops} hops"

    return result


def _find_router_for(topology: Topology, addr: IPv8Address) -> Router | None:
    """Find a router whose address matches *addr* or shares its prefix."""
    # Exact match first
    for r in topology.routers.values():
        if r.address == addr:
            return r
    # Same prefix (same AS)
    prefix = addr.prefix_str
    for r in topology.routers.values():
        if r.address.prefix_str == prefix:
            return r
    # First router with a default route
    for r in topology.routers.values():
        if "*" in r.routes:
            return r
    # Any router
    if topology.routers:
        return next(iter(topology.routers.values()))
    return None


# ---------------------------------------------------------------------------
# Pre-built topologies
# ---------------------------------------------------------------------------


def build_linear_topology(hops: int = 5) -> tuple[Topology, IPv8Address, IPv8Address]:
    """Build a linear chain of *hops* routers for testing.

    Returns ``(topology, src_address, dst_address)``.

    Layout: R0 → R1 → R2 → ... → R(hops-1)
    Each Ri has ASN 64496+i.
    """
    topo = Topology()
    for i in range(hops):
        asn = 64496 + i
        name = f"R{i}"
        routes: dict[str, str] = {}
        if i < hops - 1:
            routes["*"] = f"R{i + 1}"
        topo.add_router(name, f"{asn}.10.0.0.1", routes)

    src = topo.routers["R0"].address
    dst = topo.routers[f"R{hops - 1}"].address
    return topo, src, dst


def build_diamond_topology() -> tuple[Topology, IPv8Address, IPv8Address]:
    """Build a diamond topology for testing route selection.

    Layout::

        R0 ──→ R1 ──→ R3
         │              ↑
         └───→ R2 ──────┘

    R0 default route goes via R1 (shorter path).
    """
    topo = Topology()
    topo.add_router("R0", "64496.10.0.0.1", {"*": "R1"})
    topo.add_router("R1", "64497.10.0.0.1", {"*": "R3"})
    topo.add_router("R2", "64498.10.0.0.1", {"*": "R3"})
    topo.add_router("R3", "64499.10.0.0.1")

    src = topo.routers["R0"].address
    dst = topo.routers["R3"].address
    return topo, src, dst


def build_loop_topology() -> tuple[Topology, IPv8Address, IPv8Address]:
    """Build a topology with a routing loop for testing loop detection.

    R0 → R1 → R2 → R1 (loop)
    """
    topo = Topology()
    topo.add_router("R0", "64496.10.0.0.1", {"*": "R1"})
    topo.add_router("R1", "64497.10.0.0.1", {"*": "R2"})
    topo.add_router("R2", "64498.10.0.0.1", {"*": "R1"})  # loop back

    src = topo.routers["R0"].address
    dst = IPv8Address.parse("64500.10.0.0.1")  # unreachable
    return topo, src, dst


def build_multi_path_topology() -> tuple[Topology, IPv8Address, IPv8Address]:
    """Build a topology with prefix-specific routes.

    R0 routes 64499 prefix via R2 (direct), everything else via R1.
    """
    dst_prefix = IPv8Address.parse("64499.10.0.0.1").prefix_str
    topo = Topology()
    topo.add_router("R0", "64496.10.0.0.1", {dst_prefix: "R2", "*": "R1"})
    topo.add_router("R1", "64497.10.0.0.1", {"*": "R3"})
    topo.add_router("R2", "64498.10.0.0.1", {"*": "R3"})
    topo.add_router("R3", "64499.10.0.0.1")

    src = topo.routers["R0"].address
    dst = topo.routers["R3"].address
    return topo, src, dst
