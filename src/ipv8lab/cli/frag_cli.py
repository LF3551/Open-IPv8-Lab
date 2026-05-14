# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""CLI commands for IPv8 packet fragmentation and reassembly."""

from __future__ import annotations

import json

import typer
from rich.console import Console
from rich.table import Table

from ipv8lab.address import IPv8Address
from ipv8lab.fragmentation import (
    DEFAULT_MTU,
    FLAG_DF,
    FLAG_MF,
    FRAG_UNIT,
    HEADER_SIZE,
    can_fragment,
    fragment,
    fragment_and_reassemble,
    needs_fragmentation,
)
from ipv8lab.packet import IPv8Packet

app = typer.Typer(no_args_is_help=True)
console = Console()


@app.command("fragment")
def cmd_fragment(
    src: str = typer.Option("64496.10.0.1.1", "--src", help="Source IPv8 address."),
    dst: str = typer.Option("64497.10.0.1.100", "--dst", help="Destination IPv8 address."),
    payload_size: int = typer.Option(3000, "--size", "-s", help="Payload size in bytes."),
    mtu: int = typer.Option(DEFAULT_MTU, "--mtu", "-m", help="MTU in bytes."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Fragment a packet into pieces fitting the given MTU."""
    try:
        src_addr = IPv8Address.parse(src)
        dst_addr = IPv8Address.parse(dst)
    except (ValueError, TypeError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    pkt = IPv8Packet(
        src=src_addr, dst=dst_addr,
        payload=bytes(payload_size),
        identification=1,
    )

    try:
        frags = fragment(pkt, mtu)
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    if as_json:
        frag_list = []
        for i, f in enumerate(frags):
            frag_list.append({
                "index": i,
                "offset": f.fragment_offset,
                "offset_bytes": f.fragment_offset * FRAG_UNIT,
                "payload_size": len(f.payload),
                "mf": bool(f.flags & FLAG_MF),
                "total_size": HEADER_SIZE + len(f.payload),
            })
        typer.echo(json.dumps({
            "original_size": HEADER_SIZE + payload_size,
            "mtu": mtu,
            "fragments": frag_list,
            "count": len(frags),
        }, indent=2))
        return

    console.print(f"[bold]Fragmentation[/bold]: {HEADER_SIZE + payload_size}B packet → MTU {mtu}")
    table = Table(box=None)
    table.add_column("#", style="bold")
    table.add_column("Offset")
    table.add_column("Offset (bytes)")
    table.add_column("Payload")
    table.add_column("Total")
    table.add_column("MF")

    for i, f in enumerate(frags):
        table.add_row(
            str(i), str(f.fragment_offset),
            str(f.fragment_offset * FRAG_UNIT),
            f"{len(f.payload)}B",
            f"{HEADER_SIZE + len(f.payload)}B",
            "✓" if f.flags & FLAG_MF else "—",
        )
    console.print(table)
    console.print(f"\n[green]✓[/green] {len(frags)} fragments")


@app.command("reassemble")
def cmd_reassemble(
    src: str = typer.Option("64496.10.0.1.1", "--src", help="Source IPv8 address."),
    dst: str = typer.Option("64497.10.0.1.100", "--dst", help="Destination IPv8 address."),
    payload_size: int = typer.Option(3000, "--size", "-s", help="Payload size in bytes."),
    mtu: int = typer.Option(DEFAULT_MTU, "--mtu", "-m", help="MTU in bytes."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Fragment and reassemble a packet (round-trip validation)."""
    try:
        src_addr = IPv8Address.parse(src)
        dst_addr = IPv8Address.parse(dst)
    except (ValueError, TypeError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    payload = bytes(range(256)) * (payload_size // 256) + bytes(range(payload_size % 256))
    pkt = IPv8Packet(
        src=src_addr, dst=dst_addr,
        payload=payload,
        identification=1,
    )

    try:
        frags = fragment(pkt, mtu)
        result = fragment_and_reassemble(pkt, mtu)
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    ok = result.payload == pkt.payload

    if as_json:
        typer.echo(json.dumps({
            "original_size": HEADER_SIZE + payload_size,
            "mtu": mtu,
            "fragments": len(frags),
            "reassembled_size": HEADER_SIZE + len(result.payload),
            "payload_match": ok,
        }, indent=2))
        return

    status = "[green]✓ PASS[/green]" if ok else "[red]✗ FAIL[/red]"
    console.print(f"[bold]Round-trip[/bold]: {HEADER_SIZE + payload_size}B → {len(frags)} frags @ MTU {mtu} → {HEADER_SIZE + len(result.payload)}B  {status}")


@app.command("info")
def cmd_info(
    payload_size: int = typer.Option(3000, "--size", "-s", help="Payload size in bytes."),
    mtu: int = typer.Option(DEFAULT_MTU, "--mtu", "-m", help="MTU in bytes."),
    df: bool = typer.Option(False, "--df", help="Set Don't Fragment flag."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Show fragmentation info for a given packet size and MTU."""
    pkt = IPv8Packet(
        src=IPv8Address.parse("64496.10.0.1.1"),
        dst=IPv8Address.parse("64497.10.0.1.1"),
        payload=bytes(payload_size),
        flags=FLAG_DF if df else 0,
    )

    total = HEADER_SIZE + payload_size
    max_payload_per_frag = ((mtu - HEADER_SIZE) // FRAG_UNIT) * FRAG_UNIT
    frag_count = 1
    if needs_fragmentation(pkt, mtu) and can_fragment(pkt):
        frag_count = (payload_size + max_payload_per_frag - 1) // max_payload_per_frag

    info = {
        "total_size": total,
        "header_size": HEADER_SIZE,
        "payload_size": payload_size,
        "mtu": mtu,
        "max_payload_per_fragment": max_payload_per_frag,
        "fragment_unit": FRAG_UNIT,
        "needs_fragmentation": needs_fragmentation(pkt, mtu),
        "can_fragment": can_fragment(pkt),
        "df_flag": df,
        "estimated_fragments": frag_count,
    }

    if as_json:
        typer.echo(json.dumps(info, indent=2))
        return

    console.print("[bold]Fragmentation Info[/bold]")
    for k, v in info.items():
        label = k.replace("_", " ").title()
        console.print(f"  {label}: {v}")


@app.command("demo")
def cmd_demo(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Run a fragmentation/reassembly demo with various MTU sizes."""
    scenarios = [
        ("Small packet, large MTU", 100, 1500),
        ("Exact fit", 1472, 1500),
        ("Just over MTU", 1473, 1500),
        ("Large payload, default MTU", 5000, 1500),
        ("Tiny MTU", 1000, 100),
        ("Large payload, tiny MTU", 3000, 64),
    ]

    results: list[dict[str, object]] = []
    for label, size, mtu in scenarios:
        pkt = IPv8Packet(
            src=IPv8Address.parse("64496.10.0.1.1"),
            dst=IPv8Address.parse("64497.10.0.1.100"),
            payload=bytes(range(256)) * (size // 256) + bytes(range(size % 256)),
            identification=len(results) + 1,
        )
        frags = fragment(pkt, mtu)
        reassembled = fragment_and_reassemble(pkt, mtu)
        ok = reassembled.payload == pkt.payload
        results.append({
            "label": label,
            "payload_size": size,
            "mtu": mtu,
            "fragments": len(frags),
            "match": ok,
        })

    if as_json:
        typer.echo(json.dumps({"scenarios": results}, indent=2))
        return

    table = Table(title="Fragmentation Demo", box=None)
    table.add_column("Scenario", style="bold")
    table.add_column("Payload")
    table.add_column("MTU")
    table.add_column("Fragments")
    table.add_column("Match")

    for r in results:
        match = "[green]✓[/green]" if r["match"] else "[red]✗[/red]"
        table.add_row(
            str(r["label"]), f"{r['payload_size']}B", str(r["mtu"]),
            str(r["fragments"]), match,
        )
    console.print(table)
