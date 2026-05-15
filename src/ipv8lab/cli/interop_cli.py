# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""CLI for Inter-Company Interop and Two-XLATE8 model (Sections 4.6–4.7)."""

from __future__ import annotations

import json

import typer

from ipv8lab.interop import (
    INTEROP_PREFIX,
    TwoXLATE8Bridge,
    is_interop_prefix,
    make_interop_bridge,
    validate_interop_isolation,
)

app = typer.Typer(no_args_is_help=True)

# Module-level state
_bridge: TwoXLATE8Bridge | None = None


def _ensure_bridge() -> TwoXLATE8Bridge:
    global _bridge
    if _bridge is None:
        _bridge = make_interop_bridge()
    return _bridge


# -- commands ----------------------------------------------------------------


@app.command()
def init(
    a_name: str = typer.Option("Company-A", help="Company A name"),
    a_prefix: str = typer.Option("127.1.0.0", help="Company A internal zone prefix"),
    b_name: str = typer.Option("Company-B", help="Company B name"),
    b_prefix: str = typer.Option("127.2.0.0", help="Company B internal zone prefix"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Initialise Two-XLATE8 bridge between two companies (Section 4.7)."""
    global _bridge
    _bridge = make_interop_bridge(a_name, a_prefix, b_name, b_prefix)
    d = {
        "company_a": {"name": a_name, "prefix": a_prefix},
        "company_b": {"name": b_name, "prefix": b_prefix},
        "interop_prefix": INTEROP_PREFIX,
    }
    if as_json:
        typer.echo(json.dumps(d))
    else:
        typer.echo(f"Bridge initialised: {a_name} ({a_prefix}) ↔ {b_name} ({b_prefix})")
        typer.echo(f"Interop prefix: {INTEROP_PREFIX}")


@app.command()
def expose(
    company: str = typer.Argument(..., help="Company side: A or B"),
    internal: str = typer.Argument(..., help="Internal address (e.g. 127.1.0.0.10.0.0.5)"),
    interop_host: str = typer.Argument(..., help="Host part in interop space (e.g. 10.0.0.5)"),
    port: int = typer.Option(443, help="Service port"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Expose an internal service on the 127.127.0.0 interop DMZ."""
    bridge = _ensure_bridge()
    engine = bridge.engine_a if company.upper() == "A" else bridge.engine_b
    entry = engine.expose_service(internal, interop_host, internal_port=port, interop_port=port)
    d = {
        "company": engine.company_name,
        "internal": entry.internal_address,
        "interop": entry.interop_address,
        "port": port,
    }
    if as_json:
        typer.echo(json.dumps(d))
    else:
        typer.echo(f"{engine.company_name}: {entry.internal_address} → {entry.interop_address} :{port}")


@app.command()
def send(
    from_company: str = typer.Argument(..., help="Sender: A or B"),
    src: str = typer.Argument(..., help="Source internal address"),
    dst_host: str = typer.Argument(..., help="Destination host in interop space"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Simulate a packet through the Two-XLATE8 bridge."""
    bridge = _ensure_bridge()
    flow = bridge.send(from_company, src, dst_host)
    if as_json:
        typer.echo(json.dumps([
            {"step": e.step, "src": e.src, "dst": e.dst, "note": e.note}
            for e in flow
        ]))
    else:
        for e in flow:
            typer.echo(f"[{e.step}] {e.src} → {e.dst}  ({e.note})")


@app.command()
def table(
    company: str = typer.Argument(..., help="Company side: A or B"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Show XLATE8 interop translation table for a company."""
    bridge = _ensure_bridge()
    engine = bridge.engine_a if company.upper() == "A" else bridge.engine_b
    entries = engine.entries()
    if as_json:
        typer.echo(json.dumps([
            {"internal": e.internal_address, "interop": e.interop_address, "port": e.internal_port}
            for e in entries
        ]))
    else:
        if not entries:
            typer.echo(f"{engine.company_name}: no interop mappings.")
            return
        for e in entries:
            typer.echo(f"{e.internal_address} ↔ {e.interop_address} :{e.internal_port}")


@app.command()
def validate(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Validate interop isolation — neither company sees the other's internals."""
    bridge = _ensure_bridge()
    violations = validate_interop_isolation(bridge)
    d = {"ok": len(violations) == 0, "violations": violations}
    if as_json:
        typer.echo(json.dumps(d))
    else:
        if not violations:
            typer.echo("Isolation OK — no address leaks.")
        else:
            for v in violations:
                typer.echo(f"VIOLATION: {v}")


@app.command()
def events(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Show all interop flow events."""
    bridge = _ensure_bridge()
    evts = bridge.events
    if as_json:
        typer.echo(json.dumps([
            {"step": e.step, "src": e.src, "dst": e.dst, "note": e.note}
            for e in evts
        ]))
    else:
        if not evts:
            typer.echo("No events yet.")
            return
        for e in evts:
            typer.echo(f"[{e.step}] {e.src} → {e.dst}  ({e.note})")


@app.command()
def check(
    address: str = typer.Argument(..., help="Address to check"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Check if an address is in the 127.127.0.0 interop space."""
    result = is_interop_prefix(address)
    d = {"address": address, "is_interop": result, "interop_prefix": INTEROP_PREFIX}
    if as_json:
        typer.echo(json.dumps(d))
    else:
        typer.echo(f"{address}: {'interop prefix' if result else 'not interop prefix'}")


@app.command()
def status(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Show Two-XLATE8 bridge status."""
    bridge = _ensure_bridge()
    d = {
        "company_a": {
            "name": bridge.engine_a.company_name,
            "prefix": bridge.engine_a.internal_prefix,
            "mappings": bridge.engine_a.size,
        },
        "company_b": {
            "name": bridge.engine_b.company_name,
            "prefix": bridge.engine_b.internal_prefix,
            "mappings": bridge.engine_b.size,
        },
        "interop_prefix": INTEROP_PREFIX,
        "events": len(bridge.events),
    }
    if as_json:
        typer.echo(json.dumps(d))
    else:
        typer.echo(f"Company A: {bridge.engine_a.company_name} ({bridge.engine_a.internal_prefix}) — {bridge.engine_a.size} mappings")
        typer.echo(f"Company B: {bridge.engine_b.company_name} ({bridge.engine_b.internal_prefix}) — {bridge.engine_b.size} mappings")
        typer.echo(f"Interop prefix: {INTEROP_PREFIX}")
        typer.echo(f"Events: {len(bridge.events)}")


@app.command()
def demo(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Run a full Two-XLATE8 interop demo (Section 4.7)."""
    global _bridge
    _bridge = make_interop_bridge("Acme-Corp", "127.1.0.0", "Globex-Inc", "127.2.0.0")

    # Expose services
    _bridge.engine_a.expose_service("127.1.0.0.10.0.0.5", "10.0.0.5", internal_port=443, interop_port=443)
    _bridge.engine_b.expose_service("127.2.0.0.10.0.0.10", "10.0.0.10", internal_port=443, interop_port=443)

    # A → B
    flow_ab = _bridge.send("A", "127.1.0.0.10.0.0.5", "10.0.0.10")
    # B → A
    flow_ba = _bridge.send("B", "127.2.0.0.10.0.0.10", "10.0.0.5")

    violations = validate_interop_isolation(_bridge)

    if as_json:
        typer.echo(json.dumps({
            "a_to_b": [{"step": e.step, "src": e.src, "dst": e.dst, "note": e.note} for e in flow_ab],
            "b_to_a": [{"step": e.step, "src": e.src, "dst": e.dst, "note": e.note} for e in flow_ba],
            "isolation_ok": len(violations) == 0,
        }))
    else:
        typer.echo("=== Acme-Corp → Globex-Inc ===")
        for e in flow_ab:
            typer.echo(f"  [{e.step}] {e.src} → {e.dst}")
        typer.echo("=== Globex-Inc → Acme-Corp ===")
        for e in flow_ba:
            typer.echo(f"  [{e.step}] {e.src} → {e.dst}")
        typer.echo(f"Isolation: {'OK' if not violations else 'VIOLATIONS FOUND'}")
