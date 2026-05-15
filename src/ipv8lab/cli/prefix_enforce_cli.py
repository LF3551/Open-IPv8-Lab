# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""CLI for /16 Minimum Prefix Enforcement at eBGP8 boundaries per Section 19.7."""

from __future__ import annotations

import json

import typer

from ipv8lab.address import IPv8Address
from ipv8lab.prefix_enforce import (
    BGP8PrefixAd,
    MIN_PREFIX_LENGTH,
    PrefixEnforcer,
)

app = typer.Typer(no_args_is_help=True)

_enforcer: PrefixEnforcer | None = None


def _get_enforcer() -> PrefixEnforcer:
    global _enforcer
    if _enforcer is None:
        _enforcer = PrefixEnforcer()
    return _enforcer


@app.command()
def init(
    router_id: str = typer.Option("border-1", help="Router identifier"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Initialise the prefix enforcer."""
    global _enforcer
    _enforcer = PrefixEnforcer(router_id=router_id)
    if as_json:
        typer.echo(json.dumps(_enforcer.summary()))
    else:
        typer.echo(f"Prefix enforcer initialised on {router_id} (min /{MIN_PREFIX_LENGTH})")


@app.command()
def check(
    prefix: str = typer.Argument(..., help="BGP8 advertised prefix (ASN.n.n.n.n)"),
    length: int = typer.Argument(..., help="Prefix length (e.g. 16, 24)"),
    peer_asn: int = typer.Option(0, help="Peer ASN"),
    interface: str = typer.Option("eth0", help="Interface"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Check a BGP8 prefix advertisement against /16 minimum."""
    e = _get_enforcer()
    addr = IPv8Address.parse(prefix)
    ad = BGP8PrefixAd(prefix=addr, prefix_length=length, peer_asn=peer_asn)
    result = e.filter_advertisement(ad, interface)
    d = {
        "prefix": ad.cidr,
        "prefix_length": ad.prefix_length,
        "min_allowed": MIN_PREFIX_LENGTH,
        "action": result.action.value,
        "reason": result.reason,
        "alert": result.alert.to_dict() if result.alert else None,
    }
    if as_json:
        typer.echo(json.dumps(d))
    else:
        typer.echo(f"{result.action.value.upper()}: {ad.cidr}")
        if result.reason:
            typer.echo(f"  {result.reason}")


@app.command()
def alerts(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Show all SEC-ALERT events."""
    e = _get_enforcer()
    data = [a.to_dict() for a in e.alerts]
    if as_json:
        typer.echo(json.dumps(data))
    else:
        if not data:
            typer.echo("No alerts.")
        else:
            for a in e.alerts:
                typer.echo(f"  {a.severity}: {a.violation} on {a.interface} ({a.prefix})")


@app.command()
def status(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Show enforcer status."""
    e = _get_enforcer()
    d = e.summary()
    if as_json:
        typer.echo(json.dumps(d))
    else:
        typer.echo(f"Router:   {d['router_id']}")
        typer.echo(f"Min /:    {d['min_prefix_length']}")
        typer.echo(f"Accepted: {d['accepted']}")
        typer.echo(f"Rejected: {d['rejected']}")
        typer.echo(f"Alerts:   {d['alert_count']}")
