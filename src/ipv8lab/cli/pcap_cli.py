# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""CLI commands for PCAP export and Wireshark integration."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from ipv8lab.address import IPv8Address
from ipv8lab.packet import IPv8Packet
from ipv8lab.pcap_export import (
    PcapReader,
    PcapWriter,
    generate_lua_dissector,
    iv8cap_to_pcap,
    save_lua_dissector,
)

app = typer.Typer(no_args_is_help=True)
console = Console()


@app.command("export")
def export_pcap(
    input_path: str = typer.Argument(help="Input .iv8cap file path."),
    output_path: str = typer.Argument(help="Output .pcap file path."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Convert an .iv8cap capture file to .pcap format."""
    inp = Path(input_path)
    if not inp.exists():
        console.print(f"[red]Error:[/red] File not found: {input_path}")
        raise typer.Exit(1)

    try:
        stats = iv8cap_to_pcap(inp, output_path)
    except (ValueError, OSError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    if as_json:
        typer.echo(json.dumps({
            "input": input_path,
            "output": output_path,
            "packets": stats.packets,
            "bytes_total": stats.bytes_total,
            "file_size": stats.file_size,
        }, indent=2))
        return

    console.print(f"[green]✓[/green] Exported {stats.packets} packets to {output_path} ({stats.file_size} bytes)")


@app.command("inspect")
def inspect_pcap(
    path: str = typer.Argument(help="Path to .pcap file."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Inspect a .pcap file and show IPv8 packets."""
    p = Path(path)
    if not p.exists():
        console.print(f"[red]Error:[/red] File not found: {path}")
        raise typer.Exit(1)

    try:
        reader = PcapReader.from_file(p)
    except (ValueError, OSError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    if as_json:
        pkts = []
        for cap in reader.packets:
            pkts.append({
                "timestamp_ns": cap.timestamp_ns,
                "src": str(cap.packet.src),
                "dst": str(cap.packet.dst),
                "protocol": cap.packet.protocol,
                "ttl": cap.packet.ttl,
                "payload_size": len(cap.packet.payload),
            })
        typer.echo(json.dumps({
            "file": path,
            "link_type": reader.link_type,
            "packets": pkts,
            "total": reader.packet_count,
        }, indent=2))
        return

    console.print(f"[bold]PCAP: {path}[/bold] (link_type={reader.link_type})")
    if not reader.packets:
        console.print("[dim]No IPv8 packets found.[/dim]")
        return

    table = Table(box=None)
    table.add_column("#", style="bold")
    table.add_column("Time (ns)")
    table.add_column("Source", style="cyan")
    table.add_column("Destination", style="cyan")
    table.add_column("Proto")
    table.add_column("TTL")
    table.add_column("Payload")

    for i, cap in enumerate(reader.packets, 1):
        table.add_row(
            str(i), str(cap.timestamp_ns),
            str(cap.packet.src), str(cap.packet.dst),
            str(cap.packet.protocol), str(cap.packet.ttl),
            str(len(cap.packet.payload)) + "B",
        )
    console.print(table)


@app.command("write")
def write_pcap(
    output_path: str = typer.Argument(help="Output .pcap file path."),
    src: str = typer.Option("64496-10.0.1.1", "--src", help="Source IPv8 address."),
    dst: str = typer.Option("64497-10.0.1.1", "--dst", help="Destination IPv8 address."),
    payload: str = typer.Option("hello", "--payload", help="Packet payload."),
    count: int = typer.Option(1, "--count", "-n", help="Number of packets."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Write IPv8 packets directly to a .pcap file."""
    try:
        src_addr = IPv8Address.parse(src)
        dst_addr = IPv8Address.parse(dst)
    except (ValueError, TypeError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    writer = PcapWriter()
    for i in range(count):
        pkt = IPv8Packet(
            src=src_addr, dst=dst_addr,
            payload=payload.encode(),
            identification=i,
        )
        writer.add_packet(pkt, timestamp_ns=i * 1_000_000_000)

    stats = writer.save(output_path)

    if as_json:
        typer.echo(json.dumps({
            "output": output_path,
            "packets": stats.packets,
            "bytes_total": stats.bytes_total,
            "file_size": stats.file_size,
        }, indent=2))
        return

    console.print(f"[green]✓[/green] Wrote {stats.packets} packets to {output_path} ({stats.file_size} bytes)")


@app.command("dissector")
def gen_dissector(
    output: str = typer.Option("", "--output", "-o", help="Output file path (default: stdout)."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Generate Wireshark Lua dissector for IPv8 protocol."""
    lua = generate_lua_dissector()

    if output:
        save_lua_dissector(output)
        if as_json:
            typer.echo(json.dumps({"output": output, "size": len(lua)}, indent=2))
        else:
            console.print(f"[green]✓[/green] Dissector written to {output}")
        return

    if as_json:
        typer.echo(json.dumps({"dissector": lua}, indent=2))
    else:
        typer.echo(lua)


@app.command("demo")
def run_demo(
    output: str = typer.Option("demo.pcap", "--output", "-o", help="Output .pcap file."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Generate a demo .pcap with sample IPv8 packets."""
    writer = PcapWriter()

    packets_data = [
        ("64496-10.0.1.1", "64497-10.0.1.100", b"GET /index.html"),
        ("64497-10.0.1.100", "64496-10.0.1.1", b"HTTP/1.1 200 OK"),
        ("64496-10.0.1.1", "64498-10.0.2.50", b"DNS QUERY web.iv8"),
        ("64498-10.0.2.50", "64496-10.0.1.1", b"DNS REPLY 64499-10.0.1.42"),
        ("64496-10.0.1.1", "64499-10.0.1.42", b"CONNECT"),
        ("64499-10.0.1.42", "64496-10.0.1.1", b"ACK"),
    ]

    for i, (s, d, payload) in enumerate(packets_data):
        pkt = IPv8Packet(
            src=IPv8Address.parse(s),
            dst=IPv8Address.parse(d),
            payload=payload,
            identification=i + 1,
        )
        writer.add_packet(pkt, timestamp_ns=i * 500_000_000)

    stats = writer.save(output)

    if as_json:
        typer.echo(json.dumps({
            "output": output,
            "packets": stats.packets,
            "bytes_total": stats.bytes_total,
            "file_size": stats.file_size,
        }, indent=2))
        return

    console.print("[bold]PCAP Demo[/bold]")
    for i, (s, d, payload) in enumerate(packets_data, 1):
        console.print(f"  #{i} {s} → {d}: {payload.decode()}")
    console.print(f"\n[green]✓[/green] {stats.packets} packets → {output} ({stats.file_size} bytes)")
