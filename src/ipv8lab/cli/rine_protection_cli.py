# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""CLI for RINE Prefix Protection per Section 19.3."""

from __future__ import annotations

import json

import typer

from ipv8lab.address import IPv8Address
from ipv8lab.rine_protection import (
    InterfaceType,
    RINEPrefixFilter,
    is_rine_prefix,
)

app = typer.Typer(no_args_is_help=True)

_filter: RINEPrefixFilter | None = None


def _get_filter() -> RINEPrefixFilter:
    global _filter
    if _filter is None:
        _filter = RINEPrefixFilter()
    return _filter


@app.command()
def init(
    router_id: str = typer.Option("border-1", help="Router identifier"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Initialise the RINE prefix filter."""
    global _filter
    _filter = RINEPrefixFilter(router_id=router_id)
    if as_json:
        typer.echo(json.dumps(_filter.summary()))
    else:
        typer.echo(f"RINE prefix filter initialised on {router_id}")


@app.command(name="check")
def check_packet(
    address: str = typer.Argument(..., help="IPv8 address to check"),
    interface: str = typer.Option("eth0", help="Interface name"),
    iface_type: str = typer.Option("external", help="Interface type: peering|external|internal"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Check a packet against the RINE prefix filter."""
    f = _get_filter()
    addr = IPv8Address.parse(address)
    result = f.filter_packet(addr, interface, InterfaceType(iface_type))
    d = {
        "address": addr.full_notation,
        "is_rine": is_rine_prefix(addr),
        "action": result.action.value,
        "reason": result.reason,
        "alert": result.alert.to_dict() if result.alert else None,
    }
    if as_json:
        typer.echo(json.dumps(d))
    else:
        typer.echo(f"{result.action.value.upper()}: {addr.full_notation}")
        if result.reason:
            typer.echo(f"  {result.reason}")


@app.command(name="bgp8")
def check_bgp8(
    prefix: str = typer.Argument(..., help="BGP8 advertised prefix"),
    interface: str = typer.Option("eth0", help="eBGP8 interface"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Check a BGP8 advertisement against the RINE filter."""
    f = _get_filter()
    addr = IPv8Address.parse(prefix)
    result = f.filter_bgp8_advertisement(addr, interface)
    d = {
        "prefix": addr.full_notation,
        "action": result.action.value,
        "reason": result.reason,
        "alert": result.alert.to_dict() if result.alert else None,
    }
    if as_json:
        typer.echo(json.dumps(d))
    else:
        typer.echo(f"{result.action.value.upper()}: {addr.full_notation}")
        if result.reason:
            typer.echo(f"  {result.reason}")


@app.command()
def alerts(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Show all SEC-ALERT events."""
    f = _get_filter()
    data = [a.to_dict() for a in f.alerts]
    if as_json:
        typer.echo(json.dumps(data))
    else:
        if not data:
            typer.echo("No alerts.")
        else:
            for a in f.alerts:
                typer.echo(f"  {a.severity}: {a.violation} on {a.interface} ({a.address})")


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
        typer.echo(f"Router:  {d['router_id']}")
        typer.echo(f"Alerts:  {d['alert_count']}")
