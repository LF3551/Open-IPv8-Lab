# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""CLI commands for routing simulation."""

from pathlib import Path

import typer
from rich.console import Console

from ipv8lab.errors import IPv8LabError
from ipv8lab.simulator import NetworkSimulator

app = typer.Typer(no_args_is_help=True)
console = Console()


@app.command("simulate")
def simulate(
    config: str = typer.Option(..., "--config", "-c", help="Path to YAML network config."),
    src: str = typer.Option(None, help="Source node name (default: first host node)."),
    dst: str = typer.Option(None, help="Destination address (default: second host address)."),
    payload: str = typer.Option("hello", help="Payload string."),
) -> None:
    """Run a routing simulation from a YAML config file."""
    path = Path(config)
    if not path.exists():
        console.print(f"[red]Error:[/red] Config not found: {config}")
        raise typer.Exit(1)

    try:
        sim = NetworkSimulator.load_config(path)
    except Exception as exc:
        console.print(f"[red]Error loading config:[/red] {exc}")
        raise typer.Exit(1)

    # Auto-detect src / dst if not provided
    host_nodes = [
        n for n in sim.nodes.values() if not n.name.startswith("router")
    ]
    if src is None:
        if not host_nodes:
            console.print("[red]No host nodes found in config.[/red]")
            raise typer.Exit(1)
        src = host_nodes[0].name

    if dst is None:
        if len(host_nodes) < 2:
            console.print("[red]Need at least 2 host nodes for auto-detect.[/red]")
            raise typer.Exit(1)
        dst = host_nodes[1].address.canonical

    console.print(f"[bold]Network:[/bold] {sim.name}")
    console.print(f"[bold]From:[/bold] {src} → [bold]To:[/bold] {dst}")
    console.print(f"[bold]Destination:[/bold] {dst}")
    console.print(f"[bold]Payload:[/bold] {payload}")
    console.print()

    try:
        trace = sim.send(src, dst, payload)
    except (IPv8LabError, KeyError) as exc:
        console.print(f"[red]Simulation error:[/red] {exc}")
        raise typer.Exit(1)

    console.print("[bold green]Trace:[/bold green]")
    delivered_to: str = ""
    delivered_payload: str = ""
    for line in trace:
        if line.startswith("delivered:"):
            parts = line.split(":", 2)
            delivered_to = parts[1] if len(parts) > 1 else ""
            delivered_payload = parts[2] if len(parts) > 2 else ""
            continue
        # Render hop line with alignment
        console.print(f"  {line}")

    console.print()
    if delivered_to:
        console.print(f"Packet delivered to [bold]{delivered_to}[/bold].")
        console.print(f"Payload: {delivered_payload}")
    else:
        console.print("[red]Packet was not delivered.[/red]")
