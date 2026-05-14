# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""CLI commands for Docker-based multi-node testbed."""

from __future__ import annotations

import json

import typer
from rich.console import Console
from rich.table import Table

from ipv8lab.docker_testbed import (
    NodeRole,
    NodeSpec,
    Testbed,
    build_mesh_topology,
    build_star_topology,
    build_two_asn_topology,
)

app = typer.Typer(no_args_is_help=True)
console = Console()

# Module-level state
_testbed: Testbed | None = None


def _reset() -> None:
    global _testbed
    _testbed = None


def _get_testbed() -> Testbed:
    if _testbed is None:
        console.print("[red]Error:[/red] Testbed not initialized. Run 'init' first.")
        raise typer.Exit(1)
    return _testbed


@app.command("init")
def cmd_init(
    name: str = typer.Option("ipv8-testbed", "--name", "-n", help="Testbed name."),
    topology: str = typer.Option("", "--topology", "-t", help="Preset topology: two-asn, star, mesh."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Initialize a new Docker testbed."""
    global _testbed
    _testbed = Testbed(name=name)

    if topology:
        if topology == "two-asn":
            nodes, links = build_two_asn_topology()
        elif topology == "star":
            nodes, links = build_star_topology()
        elif topology == "mesh":
            nodes, links = build_mesh_topology()
        else:
            console.print(f"[red]Error:[/red] Unknown topology '{topology}'. Use: two-asn, star, mesh.")
            raise typer.Exit(1)
        _testbed.load_topology(nodes, links)

    if as_json:
        typer.echo(json.dumps(_testbed.to_dict(), indent=2))
    else:
        s = _testbed.stats()
        console.print(
            f"[green]✓[/green] Testbed '{name}' initialized "
            f"({s.node_count} nodes, {s.link_count} links)"
        )


@app.command("add-node")
def cmd_add_node(
    name: str = typer.Argument(help="Node name."),
    address: str = typer.Option(..., "--addr", "-a", help="IPv8 address."),
    role: str = typer.Option("host", "--role", "-r", help="Role: host, router, nat_gateway, collector."),
    gateway: str = typer.Option("", "--gateway", "-g", help="Default gateway node name."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Add a node to the testbed."""
    tb = _get_testbed()
    try:
        node_role = NodeRole(role)
    except ValueError:
        console.print(f"[red]Error:[/red] Invalid role '{role}'.")
        raise typer.Exit(1)

    spec = NodeSpec(name=name, address=address, role=node_role, gateway=gateway)
    tb.add_node(spec)

    if as_json:
        typer.echo(json.dumps(spec.to_dict(), indent=2))
    else:
        console.print(f"[green]✓[/green] Added node '{name}' ({node_role.value}) @ {address}")


@app.command("add-link")
def cmd_add_link(
    node_a: str = typer.Argument(help="First node name."),
    node_b: str = typer.Argument(help="Second node name."),
    network: str = typer.Option(..., "--net", help="Network CIDR (e.g. 10.0.1.0/24)."),
    net_name: str = typer.Option("", "--name", help="Docker network name."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Add a network link between two nodes."""
    tb = _get_testbed()
    link = tb.add_link(node_a, node_b, network, network_name=net_name)

    if as_json:
        typer.echo(json.dumps(link.to_dict(), indent=2))
    else:
        console.print(f"[green]✓[/green] Link: {node_a} ↔ {node_b} ({link.network_name})")


@app.command("generate")
def cmd_generate(
    output: str = typer.Option("./testbed-output", "--output", "-o", help="Output directory."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Generate Dockerfile, docker-compose.yml, and configs."""
    tb = _get_testbed()
    created = tb.write_output(output)

    if as_json:
        typer.echo(json.dumps({"output_dir": output, "files": created}, indent=2))
    else:
        console.print(f"[green]✓[/green] Generated {len(created)} files in {output}/")
        for f in created:
            console.print(f"  {f}")


@app.command("compose")
def cmd_compose(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON (compose structure)."),
) -> None:
    """Show the generated docker-compose.yml."""
    tb = _get_testbed()

    if as_json:
        typer.echo(json.dumps(tb.generate_compose(), indent=2))
    else:
        console.print(tb.generate_compose_yaml())


@app.command("topology")
def cmd_topology(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Show current testbed topology."""
    tb = _get_testbed()
    nodes = tb.get_nodes()
    links = tb.get_links()

    if as_json:
        typer.echo(json.dumps(tb.to_dict(), indent=2))
        return

    if not nodes:
        console.print("[dim]No nodes configured.[/dim]")
        return

    table = Table(title=f"Testbed: {tb.name}", box=None)
    table.add_column("Node", style="cyan")
    table.add_column("Address", style="green")
    table.add_column("Role")
    table.add_column("Gateway")
    table.add_column("Links", justify="right")
    for n in nodes:
        link_count = sum(1 for lk in links if n.name in (lk.node_a, lk.node_b))
        table.add_row(n.name, n.address, n.role.value, n.gateway or "-", str(link_count))
    console.print(table)


@app.command("status")
def cmd_status(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Show testbed statistics."""
    tb = _get_testbed()
    s = tb.stats()

    if as_json:
        typer.echo(json.dumps({"name": tb.name, "stats": s.to_dict()}, indent=2))
        return

    console.print(f"[bold]Testbed:[/bold] {tb.name}")
    console.print(f"  Nodes:    {s.node_count} ({s.router_count} routers, {s.host_count} hosts)")
    console.print(f"  Links:    {s.link_count}")
    console.print(f"  Networks: {s.network_count}")


@app.command("demo")
def cmd_demo(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Run a demo generating a two-ASN testbed."""
    results: list[dict[str, object]] = []

    # Two-ASN topology
    tb1 = Testbed(name="two-asn-demo")
    nodes, links = build_two_asn_topology()
    tb1.load_topology(nodes, links)
    results.append({
        "topology": "two-asn",
        "stats": tb1.stats().to_dict(),
        "compose_services": len(tb1.generate_compose()["services"]),  # type: ignore[arg-type]
    })

    # Star topology
    tb2 = Testbed(name="star-demo")
    nodes2, links2 = build_star_topology(spoke_count=5)
    tb2.load_topology(nodes2, links2)
    results.append({
        "topology": "star",
        "stats": tb2.stats().to_dict(),
        "compose_services": len(tb2.generate_compose()["services"]),  # type: ignore[arg-type]
    })

    # Mesh topology
    tb3 = Testbed(name="mesh-demo")
    nodes3, links3 = build_mesh_topology(node_count=4)
    tb3.load_topology(nodes3, links3)
    results.append({
        "topology": "mesh",
        "stats": tb3.stats().to_dict(),
        "compose_services": len(tb3.generate_compose()["services"]),  # type: ignore[arg-type]
    })

    if as_json:
        typer.echo(json.dumps({"scenarios": results}, indent=2))
        return

    for r in results:
        console.print(f"\n[bold cyan]━━━ {str(r['topology']).upper()} ━━━[/bold cyan]")
        for k, v in r.items():
            if k == "topology":
                continue
            console.print(f"  {k}: {v}")
    console.print("\n[green]✓[/green] Docker testbed demo complete")
