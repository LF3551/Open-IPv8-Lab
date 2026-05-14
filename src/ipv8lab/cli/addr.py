# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""CLI commands for IPv8 address operations."""

import json

import typer
from rich.console import Console
from rich.table import Table

from ipv8lab.address import IPv8Address, asn_to_prefix_str, prefix_str_to_asn
from ipv8lab.dump import address_summary
from ipv8lab.errors import IPv8LabError

app = typer.Typer(no_args_is_help=True)
console = Console()


@app.command("parse")
def parse_address(
    address: str = typer.Argument(help="IPv8 address to parse."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Parse an IPv8 address and display its components."""
    try:
        addr = IPv8Address.parse(address)
    except IPv8LabError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    if as_json:
        console.print(json.dumps(address_summary(address), indent=2))
        return

    parts = address.strip().split(".")
    fmt = "ASN dot notation" if len(parts) == 5 else "Full 8-octet notation"

    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column(style="bold cyan", min_width=20)
    table.add_column()

    table.add_row("Input", address)
    table.add_row("Format", fmt)
    table.add_row("ASN", str(addr.asn))
    table.add_row("Routing prefix", addr.prefix_str)
    table.add_row("Host part", addr.host_str)
    table.add_row("Full notation", addr.full_notation)

    if addr.is_ipv4_compatible():
        table.add_row("Type", "IPv4-compatible")
    elif addr.is_internal_zone():
        table.add_row("Type", "Internal zone")

    console.print(table)


@app.command("encode-asn")
def encode_asn(asn: int = typer.Argument(help="ASN value (0-4294967295).")) -> None:
    """Convert an ASN to its 4-octet routing prefix."""
    try:
        prefix = asn_to_prefix_str(asn)
    except IPv8LabError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column(style="bold cyan", min_width=20)
    table.add_column()
    table.add_row("ASN", str(asn))
    table.add_row("Routing prefix", prefix)
    console.print(table)


@app.command("decode-prefix")
def decode_prefix(
    prefix: str = typer.Argument(help="4-octet routing prefix (e.g. 0.0.251.240)."),
) -> None:
    """Convert a 4-octet routing prefix back to an ASN."""
    try:
        asn = prefix_str_to_asn(prefix)
    except (IPv8LabError, ValueError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column(style="bold cyan", min_width=20)
    table.add_column()
    table.add_row("Routing prefix", prefix)
    table.add_row("ASN", str(asn))
    console.print(table)
