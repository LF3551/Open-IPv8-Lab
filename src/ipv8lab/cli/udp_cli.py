# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""CLI commands for UDP transport experiments."""

import asyncio
from pathlib import Path

import typer
from rich.console import Console

from ipv8lab.udp_runner import UDPNetwork

app = typer.Typer(no_args_is_help=True)
console = Console()


async def _run_udp_demo(config: Path, payload: str) -> list[str]:
    net = UDPNetwork.from_yaml(config)
    await net.start_all()
    try:
        # Find host nodes
        hosts = [n for n in net.nodes.values() if not n.is_router]
        if len(hosts) < 2:
            return ["Need at least 2 host nodes"]
        src = hosts[0]
        dst = hosts[1]
        trace = await net.send_and_wait(
            src.node.name,
            dst.node.address.asn_notation,
            payload,
        )
        return trace
    finally:
        net.stop_all()


@app.command("run")
def udp_run(
    config: str = typer.Option(..., "--config", "-c", help="Path to YAML network config."),
    payload: str = typer.Option("hello via UDP", help="Payload string."),
) -> None:
    """Run a UDP transport demo — nodes communicate over real UDP sockets."""
    path = Path(config)
    if not path.exists():
        console.print(f"[red]Error:[/red] Config not found: {config}")
        raise typer.Exit(1)

    console.print("[bold]IPv8 Lab — UDP Transport Demo[/bold]")
    console.print(f"Config: {config}")
    console.print()

    trace = asyncio.run(_run_udp_demo(path, payload))

    console.print("[bold green]Trace:[/bold green]")
    for line in trace:
        console.print(f"  {line}")
