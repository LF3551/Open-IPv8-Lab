# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""CLI commands for NetFlow8 flow monitoring and telemetry export."""

from __future__ import annotations

import json

import typer
from rich.console import Console
from rich.table import Table

from ipv8lab.address import IPv8Address
from ipv8lab.netflow8 import (
    FlowCollector,
    FlowKey,
    read_nf8,
    write_nf8,
)
from ipv8lab.packet import IPv8Packet

app = typer.Typer(no_args_is_help=True)
console = Console()

# Module-level state
_collector: FlowCollector | None = None


def _reset() -> None:
    global _collector
    _collector = None


def _get_collector() -> FlowCollector:
    if _collector is None:
        console.print("[red]Error:[/red] Collector not initialized. Run 'init' first.")
        raise typer.Exit(1)
    return _collector


@app.command("init")
def cmd_init(
    active_timeout: float = typer.Option(120.0, "--active-timeout", help="Active flow timeout (seconds)."),
    idle_timeout: float = typer.Option(15.0, "--idle-timeout", help="Idle flow timeout (seconds)."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Initialize the NetFlow8 collector."""
    global _collector
    _collector = FlowCollector(active_timeout=active_timeout, idle_timeout=idle_timeout)

    if as_json:
        typer.echo(json.dumps({
            "status": "initialized",
            "active_timeout": active_timeout,
            "idle_timeout": idle_timeout,
        }, indent=2))
    else:
        console.print(
            f"[green]✓[/green] NetFlow8 collector initialized "
            f"(active={active_timeout}s, idle={idle_timeout}s)"
        )


@app.command("observe")
def cmd_observe(
    src: str = typer.Option(..., "--src", help="Source IPv8 address."),
    dst: str = typer.Option(..., "--dst", help="Destination IPv8 address."),
    src_port: int = typer.Option(0, "--sport", help="Source port."),
    dst_port: int = typer.Option(0, "--dport", help="Destination port."),
    count: int = typer.Option(1, "--count", "-n", help="Number of packets to observe."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Record one or more packet observations."""
    col = _get_collector()
    try:
        src_addr = IPv8Address.parse(src)
        dst_addr = IPv8Address.parse(dst)
    except (ValueError, TypeError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    pkt = IPv8Packet(src=src_addr, dst=dst_addr, payload=b"flow-test")
    key: FlowKey | None = None
    for _ in range(count):
        key = col.observe(pkt, src_port=src_port, dst_port=dst_port)

    if as_json:
        typer.echo(json.dumps({
            "observed": count,
            "flow_key": key.to_dict() if key else None,
            "active_flows": col.active_count,
        }, indent=2))
    else:
        console.print(f"[green]✓[/green] Observed {count} packet(s) — active flows: {col.active_count}")


@app.command("export")
def cmd_export(
    all_flows: bool = typer.Option(False, "--all", "-a", help="Force-export all flows (not just expired)."),
    output: str = typer.Option("", "--output", "-o", help="Save to .nf8 binary file."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Export expired (or all) flows."""
    col = _get_collector()

    if all_flows:
        records = col.export_all()
    else:
        records = col.export_expired()

    if output:
        n = write_nf8(records, output)
        if as_json:
            typer.echo(json.dumps({"exported": n, "file": output}, indent=2))
        else:
            console.print(f"[green]✓[/green] Exported {n} flow(s) to {output}")
        return

    if as_json:
        typer.echo(json.dumps([r.to_dict() for r in records], indent=2))
    else:
        if not records:
            console.print("[dim]No flows to export.[/dim]")
            return
        for r in records:
            console.print(
                f"  {r.key.src_addr}:{r.key.src_port} → {r.key.dst_addr}:{r.key.dst_port}  "
                f"pkts={r.packets}  bytes={r.octets}  dur={r.duration:.3f}s"
            )


@app.command("read-nf8")
def cmd_read_nf8(
    file: str = typer.Argument(help="Path to .nf8 file."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Read and display a .nf8 binary file."""
    try:
        records = read_nf8(file)
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    if as_json:
        typer.echo(json.dumps([r.to_dict() for r in records], indent=2))
        return

    if not records:
        console.print("[dim]No records in file.[/dim]")
        return

    table = Table(title=f"NetFlow8 — {file}", box=None)
    table.add_column("Source", style="cyan")
    table.add_column("Dst", style="green")
    table.add_column("Proto")
    table.add_column("Pkts", justify="right")
    table.add_column("Bytes", justify="right")
    table.add_column("Duration", justify="right")
    for r in records:
        table.add_row(
            f"{r.key.src_addr}:{r.key.src_port}",
            f"{r.key.dst_addr}:{r.key.dst_port}",
            str(r.key.protocol),
            str(r.packets),
            str(r.octets),
            f"{r.duration:.3f}s",
        )
    console.print(table)


@app.command("top")
def cmd_top(
    n: int = typer.Option(10, "--count", "-n", help="Number of top flows."),
    by: str = typer.Option("packets", "--by", "-b", help="Sort by: packets or octets."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Show top-N flows by packets or bytes."""
    col = _get_collector()

    if by == "octets":
        top = col.top_by_octets(n)
    else:
        top = col.top_talkers(n)

    if as_json:
        typer.echo(json.dumps([r.to_dict() for r in top], indent=2))
        return

    if not top:
        console.print("[dim]No flows recorded yet.[/dim]")
        return

    table = Table(title=f"Top {len(top)} flows (by {by})", box=None)
    table.add_column("#", justify="right")
    table.add_column("Source", style="cyan")
    table.add_column("Dst", style="green")
    table.add_column("Proto")
    table.add_column("Pkts", justify="right")
    table.add_column("Bytes", justify="right")
    for i, r in enumerate(top, 1):
        table.add_row(
            str(i),
            f"{r.key.src_addr}:{r.key.src_port}",
            f"{r.key.dst_addr}:{r.key.dst_port}",
            str(r.key.protocol),
            str(r.packets),
            str(r.octets),
        )
    console.print(table)


@app.command("protocols")
def cmd_protocols(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Show packet count per protocol."""
    col = _get_collector()
    breakdown = col.protocol_breakdown()

    if as_json:
        typer.echo(json.dumps(breakdown, indent=2))
        return

    if not breakdown:
        console.print("[dim]No traffic recorded.[/dim]")
        return

    table = Table(title="Protocol breakdown", box=None)
    table.add_column("Protocol", justify="right")
    table.add_column("Packets", justify="right")
    for proto, pkts in sorted(breakdown.items()):
        table.add_row(str(proto), str(pkts))
    console.print(table)


@app.command("status")
def cmd_status(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Show collector statistics."""
    col = _get_collector()

    if as_json:
        typer.echo(json.dumps(col.to_dict(), indent=2))
        return

    s = col.stats()
    console.print("[bold]NetFlow8 Collector[/bold]")
    console.print(f"  Active flows:    {s.active_flows}")
    console.print(f"  Total observed:  {s.total_observed}")
    console.print(f"  Total exported:  {s.total_exported}")
    console.print(f"  Total octets:    {s.total_octets}")


@app.command("demo")
def cmd_demo(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Run a NetFlow8 demo with sample traffic."""
    col = FlowCollector(active_timeout=120.0, idle_timeout=15.0)

    # Generate sample flows
    flows_spec = [
        ("64496-10.0.1.10", "64497-10.0.1.1", 6, 12345, 80, 50),
        ("64496-10.0.1.20", "64497-10.0.1.1", 6, 23456, 443, 30),
        ("64496-10.0.1.10", "64498-10.0.1.5", 17, 5000, 53, 10),
        ("64496-10.0.1.30", "64497-10.0.1.1", 253, 0, 0, 5),
    ]

    for src, dst, proto, sport, dport, count in flows_spec:
        pkt = IPv8Packet(
            src=IPv8Address.parse(src),
            dst=IPv8Address.parse(dst),
            protocol=proto,
            payload=b"demo-data",
        )
        for _ in range(count):
            col.observe(pkt, src_port=sport, dst_port=dport)

    records = col.export_all()
    breakdown = col.protocol_breakdown()

    results = {
        "flows_exported": len(records),
        "records": [r.to_dict() for r in records],
        "protocol_breakdown": breakdown,
        "stats": col.stats().to_dict(),
    }

    if as_json:
        typer.echo(json.dumps(results, indent=2))
        return

    console.print("\n[bold cyan]━━━ NetFlow8 Demo ━━━[/bold cyan]")
    for r in records:
        console.print(
            f"  {r.key.src_addr}:{r.key.src_port} → "
            f"{r.key.dst_addr}:{r.key.dst_port} "
            f"proto={r.key.protocol} pkts={r.packets} bytes={r.octets}"
        )
    console.print(f"\n  Protocols: {breakdown}")
    console.print(f"  Stats: {col.stats().to_dict()}")
    console.print("[green]✓[/green] NetFlow8 demo complete")
