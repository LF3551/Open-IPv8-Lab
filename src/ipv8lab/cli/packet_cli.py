# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""CLI commands for IPv8 Lab packet operations."""

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from ipv8lab.address import IPv8Address
from ipv8lab.errors import IPv8LabError
from ipv8lab.packet import IPv8Packet

app = typer.Typer(no_args_is_help=True)
console = Console()


@app.command("build")
def build_packet(
    src: str = typer.Option(..., help="Source IPv8 address."),
    dst: str = typer.Option(..., help="Destination IPv8 address."),
    payload: str = typer.Option("", help="Payload string."),
    output: Optional[str] = typer.Option(None, "-o", "--output", help="Write packet to file."),
) -> None:
    """Build an experimental IPv8 Lab packet."""
    try:
        src_addr = IPv8Address.parse(src)
        dst_addr = IPv8Address.parse(dst)
    except IPv8LabError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    pkt = IPv8Packet(src=src_addr, dst=dst_addr, payload=payload.encode())
    raw = pkt.to_bytes()

    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column(style="bold cyan", min_width=20)
    table.add_column()
    table.add_row("Source", src_addr.full_notation)
    table.add_row("Destination", dst_addr.full_notation)
    table.add_row("Payload length", f"{len(pkt.payload)} bytes")
    table.add_row("Total size", f"{len(raw)} bytes")
    table.add_row("Checksum", f"0x{pkt.checksum:08X}")
    console.print(table)

    if output:
        Path(output).write_bytes(raw)
        console.print(f"[green]Written to {output}[/green]")


@app.command("parse")
def parse_packet(
    file: str = typer.Argument(help="Path to a binary packet file."),
) -> None:
    """Parse an IPv8 Lab packet from a binary file."""
    path = Path(file)
    if not path.exists():
        console.print(f"[red]Error:[/red] File not found: {file}")
        raise typer.Exit(1)

    raw = path.read_bytes()
    try:
        pkt = IPv8Packet.from_bytes(raw)
    except IPv8LabError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column(style="bold cyan", min_width=20)
    table.add_column()
    table.add_row("Version", str(pkt.version))
    table.add_row("TTL", str(pkt.ttl))
    table.add_row("Protocol", str(pkt.protocol))
    table.add_row("Flags", str(pkt.flags))
    table.add_row("Source", pkt.src.full_notation)
    table.add_row("Destination", pkt.dst.full_notation)
    table.add_row("Payload length", f"{len(pkt.payload)} bytes")
    table.add_row("Checksum", f"0x{pkt.checksum:08X}")
    table.add_row("Payload", pkt.payload.decode(errors="replace"))
    console.print(table)
