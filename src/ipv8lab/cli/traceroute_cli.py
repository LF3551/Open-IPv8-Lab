# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""CLI commands for Traceroute8 diagnostic utility."""

from __future__ import annotations

import json

import typer
from rich.console import Console

from ipv8lab.address import IPv8Address
from ipv8lab.traceroute8 import (
    DEFAULT_MAX_HOPS,
    Topology,
    TracerouteResult,
    build_diamond_topology,
    build_linear_topology,
    build_loop_topology,
    build_multi_path_topology,
    traceroute,
)

app = typer.Typer(no_args_is_help=True)
console = Console()


def _print_result(result: TracerouteResult, as_json: bool) -> None:
    """Shared output for traceroute results."""
    if as_json:
        typer.echo(json.dumps(result.to_dict(), indent=2))
        return

    console.print(
        f"[bold]traceroute8[/bold] to {result.dst} from {result.src}, "
        f"{result.hop_count} hops max"
    )
    if not result.hops:
        console.print("[dim]No hops recorded.[/dim]")
        if result.error:
            console.print(f"[red]Error:[/red] {result.error}")
        return

    for hop in result.hops:
        status = "[green]reached[/green]" if hop.reached else hop.icmp_type.name
        console.print(
            f"  {hop.ttl:>2}  {str(hop.address):<30}  "
            f"{hop.rtt_ms:>7.2f} ms  {hop.router_name:<10}  {status}"
        )

    if result.completed:
        console.print(f"\n[green]✓[/green] Destination reached in {result.hop_count} hops")
    elif result.error:
        console.print(f"\n[red]✗[/red] {result.error}")


@app.command("run")
def cmd_run(
    src: str = typer.Argument(help="Source IPv8 address."),
    dst: str = typer.Argument(help="Destination IPv8 address."),
    hops_count: int = typer.Option(5, "--hops", "-n", help="Number of routers in auto-generated linear topology."),
    max_hops: int = typer.Option(DEFAULT_MAX_HOPS, "--max-hops", "-m", help="Maximum TTL."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Run traceroute on an auto-generated linear topology."""
    try:
        src_addr = IPv8Address.parse(src)
        dst_addr = IPv8Address.parse(dst)
    except (ValueError, TypeError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    # Build linear topology connecting src ASN to dst ASN
    topo = Topology()

    # Create intermediate routers
    topo.add_router("src", src_addr, {"*": "R1"})
    for i in range(1, hops_count):
        asn = 64500 + i
        next_hop = f"R{i + 1}" if i < hops_count - 1 else "dst"
        topo.add_router(f"R{i}", f"{asn}.10.0.0.1", {"*": next_hop})
    topo.add_router("dst", dst_addr)

    result = traceroute(topo, src_addr, dst_addr, max_hops=max_hops)
    _print_result(result, as_json)


@app.command("linear")
def cmd_linear(
    hops: int = typer.Option(5, "--hops", "-n", help="Number of routers in chain."),
    max_hops: int = typer.Option(DEFAULT_MAX_HOPS, "--max-hops", "-m", help="Maximum TTL."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Traceroute over a linear chain of routers."""
    topo, src, dst = build_linear_topology(hops)
    result = traceroute(topo, src, dst, max_hops=max_hops)
    _print_result(result, as_json)


@app.command("diamond")
def cmd_diamond(
    max_hops: int = typer.Option(DEFAULT_MAX_HOPS, "--max-hops", "-m", help="Maximum TTL."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Traceroute over a diamond topology (R0→R1→R3, R0→R2→R3)."""
    topo, src, dst = build_diamond_topology()
    result = traceroute(topo, src, dst, max_hops=max_hops)
    _print_result(result, as_json)


@app.command("loop")
def cmd_loop(
    max_hops: int = typer.Option(DEFAULT_MAX_HOPS, "--max-hops", "-m", help="Maximum TTL."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Traceroute with a routing loop (demonstrates loop detection)."""
    topo, src, dst = build_loop_topology()
    result = traceroute(topo, src, dst, max_hops=max_hops)
    _print_result(result, as_json)


@app.command("multipath")
def cmd_multipath(
    max_hops: int = typer.Option(DEFAULT_MAX_HOPS, "--max-hops", "-m", help="Maximum TTL."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Traceroute with prefix-specific routing (R0 routes 64499 via R2)."""
    topo, src, dst = build_multi_path_topology()
    result = traceroute(topo, src, dst, max_hops=max_hops)
    _print_result(result, as_json)


@app.command("demo")
def cmd_demo(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Run all demo topologies: linear, diamond, loop, multipath."""
    scenarios = [
        ("Linear (5 hops)", build_linear_topology(5)),
        ("Diamond", build_diamond_topology()),
        ("Loop detection", build_loop_topology()),
        ("Multi-path (prefix routing)", build_multi_path_topology()),
    ]

    results: list[tuple[str, TracerouteResult]] = []
    for label, (topo, src, dst) in scenarios:
        r = traceroute(topo, src, dst)
        results.append((label, r))

    if as_json:
        typer.echo(json.dumps({
            "scenarios": [
                {"label": label, **r.to_dict()}
                for label, r in results
            ],
        }, indent=2))
        return

    for label, r in results:
        console.print(f"\n[bold cyan]━━━ {label} ━━━[/bold cyan]")
        _print_result(r, False)
