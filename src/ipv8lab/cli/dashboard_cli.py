# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""CLI command for the web dashboard."""

from pathlib import Path

import typer
from rich.console import Console

from ipv8lab.dashboard import run_dashboard
from ipv8lab.simulator import NetworkSimulator

app = typer.Typer(no_args_is_help=True)
console = Console()


@app.command("serve")
def serve(
    config: str = typer.Argument(help="Path to network YAML config."),
    host: str = typer.Option("127.0.0.1", help="Bind address."),
    port: int = typer.Option(8718, help="Port number."),
) -> None:
    """Start the web dashboard for a network simulation."""
    path = Path(config)
    if not path.exists():
        console.print(f"[red]Error:[/red] Config not found: {config}")
        raise typer.Exit(1)

    sim = NetworkSimulator.load_config(path)
    console.print(f"[bold green]Loaded:[/bold green] {len(sim.nodes)} nodes")
    run_dashboard(sim, host=host, port=port)
