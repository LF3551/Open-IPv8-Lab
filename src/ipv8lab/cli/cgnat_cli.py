# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""CLI for CGNAT Behaviour simulation per Section 15."""

from __future__ import annotations

import json

import typer

from ipv8lab.address import IPv8Address
from ipv8lab.cgnat import CGNATEngine, CGNATViolation

app = typer.Typer(no_args_is_help=True)

_engine: CGNATEngine | None = None


def _get_engine() -> CGNATEngine:
    global _engine
    if _engine is None:
        _engine = CGNATEngine()
    return _engine


@app.command()
def init(
    asn: int = typer.Option(0, help="Operator ASN (0 = no ASN)"),
    pool_start: str = typer.Option("198.51.100.1", help="NAT pool start"),
    pool_end: str = typer.Option("198.51.100.254", help="NAT pool end"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Initialise the CGNAT engine."""
    global _engine
    _engine = CGNATEngine(operator_asn=asn, pool_start=pool_start, pool_end=pool_end)
    d = _engine.summary()
    if as_json:
        typer.echo(json.dumps(d))
    else:
        typer.echo(f"CGNAT initialised: ASN={asn} pool={pool_start}-{pool_end}")


@app.command()
def translate(
    address: str = typer.Argument(..., help="IPv8 address to translate"),
    port: int = typer.Option(0, help="Source port"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Translate an address through the CGNAT."""
    engine = _get_engine()
    addr = IPv8Address.parse(address)
    result = engine.translate(addr, src_port=port)
    d = {
        "original": result.original.full_notation,
        "translated": result.translated.full_notation,
        "violation": result.violation.value,
        "prefix_preserved": result.original.prefix_str == result.translated.prefix_str,
        "note": result.note,
    }
    if as_json:
        typer.echo(json.dumps(d))
    else:
        typer.echo(f"Original:   {d['original']}")
        typer.echo(f"Translated: {d['translated']}")
        typer.echo(f"RN preserved: {d['prefix_preserved']}")
        if result.violation != CGNATViolation.NONE:
            typer.echo(f"VIOLATION: {result.violation.value} — {result.note}")


@app.command()
def validate(
    original: str = typer.Argument(..., help="Original address"),
    translated: str = typer.Argument(..., help="Translated address"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Validate that a translation preserved the RN (Routing Number)."""
    engine = _get_engine()
    orig = IPv8Address.parse(original)
    trans = IPv8Address.parse(translated)
    v = engine.validate_translation(orig, trans)
    d = {"original": orig.full_notation, "translated": trans.full_notation, "violation": v.value}
    if as_json:
        typer.echo(json.dumps(d))
    else:
        if v == CGNATViolation.NONE:
            typer.echo("OK — RN preserved")
        else:
            typer.echo(f"VIOLATION: {v.value}")


@app.command()
def bindings(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Show active NAT bindings."""
    engine = _get_engine()
    data = [
        {
            "inside": b.inside.full_notation,
            "outside": b.outside.full_notation,
            "port_inside": b.port_inside,
            "port_outside": b.port_outside,
        }
        for b in engine.bindings
    ]
    if as_json:
        typer.echo(json.dumps(data))
    else:
        if not data:
            typer.echo("No active bindings.")
        else:
            for b in data:
                typer.echo(f"  {b['inside']}:{b['port_inside']} → {b['outside']}:{b['port_outside']}")


@app.command()
def flush(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Flush all NAT bindings."""
    engine = _get_engine()
    n = engine.flush()
    if as_json:
        typer.echo(json.dumps({"flushed": n}))
    else:
        typer.echo(f"Flushed {n} binding(s).")


@app.command()
def status(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Show CGNAT engine status."""
    engine = _get_engine()
    d = engine.summary()
    if as_json:
        typer.echo(json.dumps(d))
    else:
        typer.echo(f"ASN:      {d['operator_asn']}")
        typer.echo(f"Prefix:   {d['prefix']}")
        typer.echo(f"Pool:     {d['pool']}")
        typer.echo(f"Bindings: {d['active_bindings']}")
