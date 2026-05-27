# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""CLI for Interior Link Convention Protection per Section 19.4."""

from __future__ import annotations

import json

import typer

from ipv8lab.address import IPv8Address
from ipv8lab.ilink_protection import (
    InteriorLinkFilter,
    is_interior_link_host,
)

app = typer.Typer(no_args_is_help=True)

_filter: InteriorLinkFilter | None = None


def _get_filter() -> InteriorLinkFilter:
    global _filter
    if _filter is None:
        _filter = InteriorLinkFilter()
    return _filter


@app.command()
def init(
    router_id: str = typer.Option("border-1", help="Router identifier"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Initialise the interior link filter."""
    global _filter
    _filter = InteriorLinkFilter(router_id=router_id)
    if as_json:
        typer.echo(json.dumps(_filter.summary()))
    else:
        typer.echo(f"Interior link filter initialised on {router_id}")


@app.command(name="bgp8")
def check_bgp8(
    prefix: str = typer.Argument(..., help="BGP8 advertised prefix as IPv8 address (e.g. 64496-222.0.0.0 or 64496-222.0.0.0/24)."),
    interface: str = typer.Option("eth0", help="Interface"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Check a BGP8 advertisement for 222.0.0.0/8 violations."""
    f = _get_filter()
    # Strip CIDR suffix if present (e.g. "64496-222.0.0.0/24" → "64496-222.0.0.0")
    addr_str = prefix.split("/")[0]
    addr = IPv8Address.parse(addr_str)
    result = f.filter_bgp8_advertisement(addr, interface)
    d = {
        "prefix": addr.canonical,
        "is_interior_link": is_interior_link_host(addr),
        "action": result.action.value,
        "reason": result.reason,
        "trap": result.trap.to_dict() if result.trap else None,
    }
    if as_json:
        typer.echo(json.dumps(d))
    else:
        typer.echo(f"{result.action.value.upper()}: {addr.canonical}")
        if result.reason:
            typer.echo(f"  {result.reason}")


@app.command(name="packet")
def check_packet(
    address: str = typer.Argument(..., help="IPv8 address"),
    interface: str = typer.Option("eth0", help="Egress interface"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Check an egress packet for 222.0.0.0/8 violations."""
    f = _get_filter()
    addr = IPv8Address.parse(address)
    result = f.filter_packet(addr, interface)
    d = {
        "address": addr.canonical,
        "action": result.action.value,
        "reason": result.reason,
        "trap": result.trap.to_dict() if result.trap else None,
    }
    if as_json:
        typer.echo(json.dumps(d))
    else:
        typer.echo(f"{result.action.value.upper()}: {addr.canonical}")
        if result.reason:
            typer.echo(f"  {result.reason}")


@app.command()
def traps(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Show all E3 trap events."""
    f = _get_filter()
    data = [t.to_dict() for t in f.traps]
    if as_json:
        typer.echo(json.dumps(data))
    else:
        if not data:
            typer.echo("No traps.")
        else:
            for t in f.traps:
                typer.echo(f"  {t.severity}: {t.violation} on {t.interface} ({t.address})")


@app.command()
def status(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Show filter status."""
    f = _get_filter()
    d = f.summary()
    if as_json:
        typer.echo(json.dumps(d))
    else:
        typer.echo(f"Router: {d['router_id']}")
        typer.echo(f"Traps:  {d['trap_count']}")
