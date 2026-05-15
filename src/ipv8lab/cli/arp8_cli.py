# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""CLI for ARP8-driven version selection per draft-thain-ipv8-02 Section 2."""

from __future__ import annotations

import json

import typer

from ipv8lab.arp8_version import (
    ARP8VersionCache,
    NeighborCapability,
    RouterForwarder,
    TransmittedFrame,
    VersionSelector,
    has_asn_attribution,
    TRANSITION_PROPERTIES,
)

app = typer.Typer(no_args_is_help=True)

# Module-level state
_cache = ARP8VersionCache()
_router = RouterForwarder()


def _frame_dict(f: TransmittedFrame) -> dict[str, object]:
    return {
        "ip_version": f.ip_version,
        "src": f.src,
        "dst": f.dst,
        "downgraded": f.downgraded,
        "asn_attribution": has_asn_attribution(f),
    }


# -- commands ----------------------------------------------------------------


@app.command()
def discover(
    target: str = typer.Argument(..., help="Neighbor IP (r.r.r.r.n.n.n.n)"),
    ipv8_capable: bool = typer.Option(True, "--ipv8/--ipv4", help="Simulate neighbor as IPv8 or IPv4-only."),
    mac: str = typer.Option("aa:bb:cc:dd:ee:ff", help="MAC address"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Simulate dual ARP8/ARP4 probe toward a neighbor (Section 2.2)."""
    outcome = _cache.discover_neighbor(target, responds_arp8=ipv8_capable, mac_address=mac)
    if as_json:
        typer.echo(json.dumps({
            "target": outcome.target_ip,
            "probe_result": outcome.probe_result.value,
            "capability": outcome.capability.value,
            "mac": outcome.mac_address,
        }))
    else:
        typer.echo(f"Target:     {outcome.target_ip}")
        typer.echo(f"Probe:      {outcome.probe_result.value}")
        typer.echo(f"Capability: {outcome.capability.value}")
        typer.echo(f"MAC:        {outcome.mac_address}")


@app.command()
def select(
    src: str = typer.Argument(..., help="Source address (r.r.r.r.n.n.n.n)"),
    dst: str = typer.Argument(..., help="Destination address (r.r.r.r.n.n.n.n)"),
    neighbor: str = typer.Option("", help="Neighbor IP to look up in cache (defaults to dst)."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Show version selection for a destination (Section 2.3)."""
    lookup = neighbor or dst
    cap = _cache.capability_of(lookup)
    frame = VersionSelector.select(src, dst, cap)
    d = _frame_dict(frame)
    if as_json:
        typer.echo(json.dumps(d))
    else:
        typer.echo(f"IP version: {frame.ip_version}")
        typer.echo(f"Src on wire: {frame.src}")
        typer.echo(f"Dst on wire: {frame.dst}")
        typer.echo(f"Downgraded:  {frame.downgraded}")
        typer.echo(f"ASN attrib:  {has_asn_attribution(frame)}")


@app.command()
def cache(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Show ARP8 cache with capabilities."""
    entries = _cache.all_entries()
    if as_json:
        typer.echo(json.dumps([
            {
                "ip": e.ipv8_address,
                "mac": e.mac_address,
                "capability": e.capability.value,
            }
            for e in entries
        ]))
    else:
        if not entries:
            typer.echo("ARP8 cache is empty.")
            return
        for e in entries:
            typer.echo(f"{e.ipv8_address}  {e.mac_address}  {e.capability.value}")


@app.command()
def simulate(
    src: str = typer.Argument(..., help="Source IPv8 address"),
    dst: str = typer.Argument(..., help="Destination IPv8 address"),
    iface: str = typer.Option("eth0", help="Outgoing interface name"),
    next_hop: str = typer.Option("", help="Next-hop IP (defaults to dst)"),
    next_hop_ipv8: bool = typer.Option(True, "--ipv8/--ipv4", help="Next-hop capability"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Simulate router forwarding with per-interface downgrade (Section 2.4)."""
    hop = next_hop or dst
    if _router.get_interface(iface) is None:
        _router.add_interface(iface)
    ri = _router.get_interface(iface)
    assert ri is not None
    cap = NeighborCapability.IPV8 if next_hop_ipv8 else NeighborCapability.IPV4_ONLY
    from ipv8lab.arp8_version import ARP8VersionEntry
    ri.cache.learn(ARP8VersionEntry(
        ipv8_address=hop,
        mac_address="00:00:00:00:00:00",
        capability=cap,
    ))
    decision = _router.forward(src, dst, iface, hop)
    d = {
        "outgoing_interface": decision.outgoing_interface,
        "xlate8_needed": decision.xlate8_needed,
        **_frame_dict(decision.frame),
    }
    if as_json:
        typer.echo(json.dumps(d))
    else:
        typer.echo(f"Interface:   {decision.outgoing_interface}")
        typer.echo(f"IP version:  {decision.frame.ip_version}")
        typer.echo(f"Src on wire: {decision.frame.src}")
        typer.echo(f"Dst on wire: {decision.frame.dst}")
        typer.echo(f"Downgraded:  {decision.frame.downgraded}")
        typer.echo(f"XLATE8:      {decision.xlate8_needed}")
        typer.echo(f"ASN attrib:  {has_asn_attribution(decision.frame)}")


@app.command()
def status(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Show overall ARP8 version selection status."""
    entries = _cache.all_entries()
    ipv8_count = sum(1 for e in entries if e.capability == NeighborCapability.IPV8)
    ipv4_count = sum(1 for e in entries if e.capability == NeighborCapability.IPV4_ONLY)
    ifaces = _router.interfaces
    d = {
        "cache_size": _cache.size,
        "ipv8_neighbors": ipv8_count,
        "ipv4_only_neighbors": ipv4_count,
        "router_interfaces": len(ifaces),
        "transition_properties": TRANSITION_PROPERTIES,
    }
    if as_json:
        typer.echo(json.dumps(d))
    else:
        typer.echo(f"Cache size:       {_cache.size}")
        typer.echo(f"IPv8 neighbors:   {ipv8_count}")
        typer.echo(f"IPv4-only:        {ipv4_count}")
        typer.echo(f"Router ifaces:    {len(ifaces)}")
        typer.echo("--- Transition properties (Section 2.6) ---")
        for p in TRANSITION_PROPERTIES:
            typer.echo(f"  • {p}")
