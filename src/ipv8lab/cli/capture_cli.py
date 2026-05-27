# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""CLI commands for packet capture and replay."""

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from ipv8lab.capture import PacketCapture
from ipv8lab.dump import packet_summary

app = typer.Typer(no_args_is_help=True)
console = Console()


@app.command("read")
def read_capture(
    file: str = typer.Argument(help="Path to a .iv8cap text capture file (use 'pcap inspect' for binary .pcap)."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Read and display packets from an .iv8cap text capture file."""
    path = Path(file)
    if not path.exists():
        console.print(f"[red]Error:[/red] File not found: {file}")
        raise typer.Exit(1)

    try:
        cap = PacketCapture.load(path)
    except UnicodeDecodeError:
        console.print(f"[red]Error:[/red] {file} appears to be a binary file.")
        console.print("  Use [bold]pcap inspect[/bold] to read binary .pcap files.")
        raise typer.Exit(1)

    if as_json:
        items = []
        for ts, pkt in cap.replay():
            info = packet_summary(pkt)
            info["timestamp_ns"] = ts
            items.append(info)
        console.print(json.dumps(items, indent=2))
        return

    console.print(f"[bold]Capture:[/bold] {file}")
    console.print(f"[bold]Packets:[/bold] {cap.count}")
    console.print()

    for i, (ts, pkt) in enumerate(cap.replay(), 1):
        ts_ms = ts / 1_000_000
        table = Table(
            title=f"Packet #{i}  (t={ts_ms:.3f} ms)",
            show_header=False,
            box=None,
            pad_edge=False,
        )
        table.add_column(style="bold cyan", min_width=20)
        table.add_column()
        table.add_row("Source", pkt.src.full_notation)
        table.add_row("Destination", pkt.dst.full_notation)
        table.add_row("Protocol", str(pkt.protocol))
        table.add_row("Payload", pkt.payload.decode(errors="replace"))
        console.print(table)
        console.print()


@app.command("info")
def capture_info(
    file: str = typer.Argument(help="Path to a .iv8cap text capture file (use 'pcap inspect' for binary .pcap)."),
) -> None:
    """Show summary info about an .iv8cap text capture file."""
    path = Path(file)
    if not path.exists():
        console.print(f"[red]Error:[/red] File not found: {file}")
        raise typer.Exit(1)

    try:
        cap = PacketCapture.load(path)
    except UnicodeDecodeError:
        console.print(f"[red]Error:[/red] {file} appears to be a binary file.")
        console.print("  Use [bold]pcap inspect[/bold] to read binary .pcap files.")
        raise typer.Exit(1)
    packets = cap.replay()

    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column(style="bold cyan", min_width=20)
    table.add_column()
    table.add_row("File", file)
    table.add_row("Packets", str(cap.count))
    if packets:
        duration_ms = (packets[-1][0] - packets[0][0]) / 1_000_000
        table.add_row("Duration", f"{duration_ms:.3f} ms")
    console.print(table)
