# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""CLI for Address Usage Model per draft-thain-ipv8- Section 4.11."""

from __future__ import annotations

import json

import typer

from ipv8lab.address import IPv8Address
from ipv8lab.addr_usage import (
    ADDRESS_USAGE_TABLE,
    classify_address,
    usage_summary,
)

app = typer.Typer(no_args_is_help=True)


@app.command(name="table")
def show_table(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Show the full Section 4.11 address usage table."""
    if as_json:
        typer.echo(json.dumps([
            {
                "pattern": e.prefix_pattern,
                "usage": e.usage,
                "external_routing": e.external_routing.value,
                "note": e.note,
            }
            for e in ADDRESS_USAGE_TABLE
        ]))
    else:
        typer.echo(f"{'Pattern':<30} {'Usage':<35} {'Ext. Routing':<12}")
        typer.echo("-" * 77)
        for e in ADDRESS_USAGE_TABLE:
            typer.echo(f"{e.prefix_pattern:<30} {e.usage:<35} {e.external_routing.value:<12}")


@app.command()
def classify(
    address: str = typer.Argument(..., help="IPv8 address to classify"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Classify an address per the Section 4.11 usage model."""
    addr = IPv8Address.parse(address)
    d = usage_summary(addr)
    if as_json:
        typer.echo(json.dumps(d))
    else:
        typer.echo(f"Address:  {addr.canonical}")
        typer.echo(f"Pattern:  {d['pattern']}")
        typer.echo(f"Usage:    {d['usage']}")
        typer.echo(f"Routing:  {d['external_routing']}")
        typer.echo(f"Note:     {d['note']}")


@app.command()
def batch(
    addresses: list[str] = typer.Argument(..., help="Addresses to classify"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Classify multiple addresses at once."""
    results = [usage_summary(IPv8Address.parse(a)) for a in addresses]
    if as_json:
        typer.echo(json.dumps(results))
    else:
        for d in results:
            addr = IPv8Address.parse(d["address"])
            entry = classify_address(addr)
            typer.echo(f"{addr.canonical:<35} {entry.usage:<35} {entry.external_routing.value}")
