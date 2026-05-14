# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""CLI commands for TUI dashboard."""

from __future__ import annotations

import json

import typer

from ipv8lab.tui_dashboard import (
    PanelType,
    TuiDashboard,
    build_demo_data,
)

app = typer.Typer(no_args_is_help=True)


def _reset() -> None:
    """Reset module state (for testing)."""


@app.command("run")
def cmd_run(
    demo: bool = typer.Option(False, "--demo", "-d", help="Run with demo data."),
) -> None:
    """Launch the TUI dashboard."""
    if demo:
        data = build_demo_data()
    else:
        data = build_demo_data()  # Default to demo for now

    dashboard = TuiDashboard(data=data)
    dashboard.run()


@app.command("demo")
def cmd_demo(
    as_json: bool = typer.Option(False, "--json", help="Output demo data as JSON."),
) -> None:
    """Show demo data that would be displayed in the TUI."""
    data = build_demo_data()

    if as_json:
        typer.echo(json.dumps(data.to_dict(), indent=2))
        return

    from rich.console import Console
    from rich.table import Table

    console = Console()

    console.print(f"\n[bold cyan]━━━ {data.title} ━━━[/bold cyan]\n")

    # Summary
    s = data.summary()
    console.print("[bold]Summary:[/bold]")
    for k, v in s.items():
        console.print(f"  {k}: {v}")

    # Topology table
    console.print("\n[bold]Topology:[/bold]")
    table = Table(box=None)
    table.add_column("Name", style="cyan")
    table.add_column("Address", style="green")
    table.add_column("Role")
    table.add_column("Gateway")
    for n in data.nodes:
        table.add_row(n.name, n.address, n.role, n.gateway or "-")
    console.print(table)

    # Flows
    console.print(f"\n[bold]Active Flows:[/bold] {len(data.flows)}")
    for f in data.flows[:5]:
        proto = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(f.protocol, str(f.protocol))
        console.print(f"  {f.src_addr}:{f.src_port} → {f.dst_addr}:{f.dst_port} [{proto}] {f.packets} pkts")

    console.print("\n[green]✓[/green] Use 'ipv8lab tui run --demo' to launch interactive TUI")


@app.command("panels")
def cmd_panels(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """List available dashboard panels."""
    panels = [
        {"id": p.value, "name": p.value.replace("_", " ").title()}
        for p in PanelType
    ]

    if as_json:
        typer.echo(json.dumps({"panels": panels}, indent=2))
        return

    from rich.console import Console
    console = Console()
    console.print("[bold]Available panels:[/bold]")
    for p in panels:
        console.print(f"  • {p['id']}: {p['name']}")


@app.command("snapshot")
def cmd_snapshot(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Take a snapshot of current dashboard data."""
    data = build_demo_data()

    if as_json:
        typer.echo(json.dumps(data.to_dict(), indent=2))
        return

    from rich.console import Console
    console = Console()
    s = data.summary()
    console.print("[bold]Dashboard Snapshot:[/bold]")
    console.print(f"  Title:    {data.title}")
    console.print(f"  Nodes:    {s['nodes']}")
    console.print(f"  Routes:   {s['routes']}")
    console.print(f"  Flows:    {s['flows']}")
    console.print(f"  QoS:      {s['qos_classes']}")
    console.print(f"  NAT:      {s['nat_mappings']}")
    console.print(f"  Docker:   {s['docker_nodes']}")
