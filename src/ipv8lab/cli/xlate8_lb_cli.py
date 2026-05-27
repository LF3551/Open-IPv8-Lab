# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""CLI for XLATE8 Even/Odd Load Balancing per Section 15.1."""

from __future__ import annotations

import json

import typer

from ipv8lab.xlate8 import (
    EvenOddLB,
    LBStrategy,
    make_a8_pair,
)

app = typer.Typer(no_args_is_help=True)

_lb: EvenOddLB | None = None


def _get_lb() -> EvenOddLB:
    global _lb
    if _lb is None:
        pair = make_a8_pair(64496, "10.0.0")
        _lb = EvenOddLB(pair=pair)
    return _lb


@app.command()
def init(
    asn: int = typer.Option(64496, help="Destination host ASN"),
    host_base: str = typer.Option("10.0.0", help="First 3 octets of host address"),
    strategy: str = typer.Option("round_robin", help="LB strategy: passthrough|round_robin|even_only|odd_only"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Initialise the Even/Odd load balancer."""
    global _lb
    pair = make_a8_pair(asn, host_base)
    _lb = EvenOddLB(pair=pair, strategy=LBStrategy(strategy))
    d = _lb.summary()
    if as_json:
        typer.echo(json.dumps(d))
    else:
        typer.echo(f"LB initialised: even={pair.even.full_notation} odd={pair.odd.full_notation}")
        typer.echo(f"Strategy: {strategy}")


@app.command()
def connect(
    client: str = typer.Option("192.168.1.1", help="Client IPv4 address"),
    port: int = typer.Option(0, help="Client port"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Simulate a single connection through the LB."""
    lb = _get_lb()
    conn = lb.select(client_addr=client, client_port=port)
    d = {
        "client": conn.client_addr,
        "client_port": conn.client_port,
        "selected": conn.selected.full_notation,
        "parity": conn.parity.value,
        "seq": conn.seq,
    }
    if as_json:
        typer.echo(json.dumps(d))
    else:
        typer.echo(f"→ {conn.selected.full_notation} ({conn.parity.value}) seq={conn.seq}")


@app.command()
def simulate(
    client: str = typer.Option("192.168.1.1", help="Client IPv4 address"),
    count: int = typer.Option(10, help="Number of connections"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Simulate multiple connections and show distribution."""
    lb = _get_lb()
    lb.reset()
    conns = lb.distribute(client_addr=client, count=count)
    data = [
        {"seq": c.seq, "selected": c.selected.full_notation, "parity": c.parity.value}
        for c in conns
    ]
    if as_json:
        typer.echo(json.dumps({"connections": data, "stats": lb.stats}))
    else:
        for c in conns:
            typer.echo(f"  [{c.seq}] → {c.selected.full_notation} ({c.parity.value})")
        s = lb.stats
        typer.echo(f"Total: {s['total']}  Even: {s['even']}  Odd: {s['odd']}")


@app.command()
def stats(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Show current LB statistics."""
    lb = _get_lb()
    d = lb.stats
    if as_json:
        typer.echo(json.dumps(d))
    else:
        typer.echo(f"Total: {d['total']}  Even: {d['even']}  Odd: {d['odd']}")


@app.command()
def status(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Show LB module status."""
    lb = _get_lb()
    d = lb.summary()
    if as_json:
        typer.echo(json.dumps(d))
    else:
        typer.echo(f"Strategy: {lb.strategy.value}")
        typer.echo(f"Even:     {lb.pair.even.full_notation}")
        typer.echo(f"Odd:      {lb.pair.odd.full_notation}")
        s = lb.stats
        typer.echo(f"Conns:    {s['total']} (even={s['even']}, odd={s['odd']})")
