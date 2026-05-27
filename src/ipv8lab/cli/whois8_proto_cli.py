# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""CLI for standalone WHOIS8 protocol per draft-thain-whois8-."""

from __future__ import annotations

import json
import time

import typer

from ipv8lab.whois8_proto import (
    WHOIS8ASNRecord,
    WHOIS8Client,
    WHOIS8Query,
    WHOIS8Server,
    QueryType,
    RIR,
    ResponseCode,
    RouteRecord,
)

app = typer.Typer(no_args_is_help=True)

_server: WHOIS8Server | None = None
_client: WHOIS8Client | None = None


def _get_server() -> WHOIS8Server:
    global _server
    if _server is None:
        _server = WHOIS8Server()
    return _server


def _get_client() -> WHOIS8Client:
    global _client, _server
    if _server is None:
        _server = WHOIS8Server()
    if _client is None:
        _client = WHOIS8Client(server=_server)
    return _client


@app.command()
def init(
    server_id: str = typer.Option("whois8-primary", help="Server identifier"),
    secret: str = typer.Option("", help="Signing secret (empty = no signing)"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Initialise WHOIS8 server and client."""
    global _server, _client
    _server = WHOIS8Server(server_id=server_id, signing_secret=secret)
    _client = WHOIS8Client(server=_server)
    if as_json:
        typer.echo(json.dumps(_server.summary()))
    else:
        typer.echo(f"WHOIS8 server '{server_id}' initialised")


@app.command()
def register(
    asn: int = typer.Argument(..., help="ASN to register"),
    holder: str = typer.Argument(..., help="Holder name"),
    country: str = typer.Option("", help="Country code"),
    rir: str = typer.Option("ARIN", help="RIR (ARIN/RIPE/APNIC/LACNIC/AFRINIC)"),
    anycast: str = typer.Option("", help="IPv4 anycast address for 8to4"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Register an ASN in the WHOIS8 registry."""
    s = _get_server()
    record = WHOIS8ASNRecord(
        asn=asn,
        holder=holder,
        country=country,
        rir=RIR(rir),
        anycast_v4=anycast,
        created_at=time.time(),
    )
    try:
        s.register_asn(record)
    except ValueError as e:
        if as_json:
            typer.echo(json.dumps({"error": str(e)}))
        else:
            typer.echo(f"ERROR: {e}")
        raise typer.Exit(code=1) from None
    stored = s._registry[asn]  # noqa: SLF001
    if as_json:
        typer.echo(json.dumps(stored.to_dict()))
    else:
        typer.echo(f"Registered ASN {asn} ({holder})")


@app.command(name="route")
def register_route(
    asn: int = typer.Argument(..., help="ASN"),
    prefix_length: int = typer.Argument(..., help="Prefix length"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Register a route ownership record."""
    s = _get_server()
    route = RouteRecord(asn=asn, prefix_length=prefix_length)
    try:
        s.register_route(route)
    except ValueError as e:
        if as_json:
            typer.echo(json.dumps({"error": str(e)}))
        else:
            typer.echo(f"ERROR: {e}")
        raise typer.Exit(code=1) from None
    if as_json:
        typer.echo(json.dumps(route.to_dict()))
    else:
        typer.echo(f"Route /{prefix_length} registered for ASN {asn}")


@app.command()
def lookup(
    asn: int = typer.Argument(..., help="ASN to look up"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Look up an ASN via WHOIS8 client (cached)."""
    c = _get_client()
    resp = c.lookup(asn)
    if as_json:
        typer.echo(json.dumps(resp.to_dict()))
    else:
        typer.echo(f"{resp.code.value}: ASN {asn}")
        if resp.reason:
            typer.echo(f"  {resp.reason}")
        if resp.record:
            typer.echo(f"  Holder: {resp.record.holder}")


@app.command()
def validate(
    asn: int = typer.Argument(..., help="ASN"),
    prefix_length: int = typer.Argument(8, help="Prefix length"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Validate a BGP8 route advertisement via WHOIS8."""
    c = _get_client()
    resp = c.validate_route(asn, prefix_length)
    if as_json:
        typer.echo(json.dumps(resp.to_dict()))
    else:
        typer.echo(f"{resp.code.value}: ASN {asn} /{prefix_length}")
        if resp.reason:
            typer.echo(f"  {resp.reason}")


@app.command()
def anycast(
    asn: int = typer.Argument(..., help="ASN"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Look up 8to4 anycast address for an ASN."""
    c = _get_client()
    resp = c.anycast_lookup(asn)
    if as_json:
        typer.echo(json.dumps(resp.to_dict()))
    else:
        typer.echo(f"{resp.code.value}: ASN {asn}")
        if resp.record and resp.record.anycast_v4:
            typer.echo(f"  Anycast: {resp.record.anycast_v4}")
        elif resp.reason:
            typer.echo(f"  {resp.reason}")


@app.command()
def verify(
    asn: int = typer.Argument(..., help="ASN to verify"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Verify record signature integrity."""
    s = _get_server()
    query = WHOIS8Query(query_type=QueryType.RECORD_VERIFY, asn=asn)
    resp = s.handle_query(query)
    if as_json:
        typer.echo(json.dumps(resp.to_dict()))
    else:
        typer.echo(f"{resp.code.value}: ASN {asn}")
        if resp.reason:
            typer.echo(f"  {resp.reason}")


@app.command(name="list")
def list_asns(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """List all registered ASNs."""
    s = _get_server()
    asns = s.list_asns()
    if as_json:
        typer.echo(json.dumps({"asns": asns, "count": len(asns)}))
    else:
        if not asns:
            typer.echo("No ASNs registered.")
        else:
            for a in asns:
                rec = s._registry[a]  # noqa: SLF001
                typer.echo(f"  ASN {a}: {rec.holder}")


@app.command()
def cache(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Show client cache status."""
    c = _get_client()
    d = c.summary()
    if as_json:
        typer.echo(json.dumps(d))
    else:
        typer.echo(f"Cache size: {d['cache_size']}")
        typer.echo(f"Hits:       {d['cache_hits']}")
        typer.echo(f"Misses:     {d['cache_misses']}")


@app.command()
def demo(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Run a self-contained WHOIS8 demo (register, route, lookup, validate)."""
    server = WHOIS8Server(server_id="whois8-demo")
    client = WHOIS8Client(server=server)

    asns = [
        (64496, "ACME Corp", "US", RIR.ARIN),
        (64497, "BetaCo", "DE", RIR.RIPE),
        (64498, "GammaTel", "JP", RIR.APNIC),
    ]
    for asn, holder, country, rir in asns:
        server.register_asn(WHOIS8ASNRecord(
            asn=asn, holder=holder, country=country, rir=rir, created_at=time.time(),
        ))

    server.register_route(RouteRecord(asn=64496, prefix_length=16))
    server.register_route(RouteRecord(asn=64497, prefix_length=16))

    steps = []
    for asn, holder, _, _ in asns:
        resp = client.lookup(asn)
        ok = resp.code == ResponseCode.OK and resp.record is not None
        steps.append({"step": f"lookup_{asn}", "ok": ok, "holder": holder})

    resp_route = client.validate_route(64496, 16)
    steps.append({"step": "route_validate_64496", "ok": resp_route.code == ResponseCode.OK})

    if as_json:
        typer.echo(json.dumps({"steps": steps, "summary": server.summary()}))
        return

    typer.echo("WHOIS8 Demo")
    typer.echo(f"  Server: {server.server_id}")
    for s in steps:
        mark = "✓" if s["ok"] else "✗"
        detail = s.get("holder", "")
        typer.echo(f"  {mark}  {s['step']}" + (f": {detail}" if detail else ""))
    sm = server.summary()
    typer.echo(f"\nRegistered: {sm['registered_asns']} ASNs, {sm['registered_routes']} routes")
    all_ok = all(s["ok"] for s in steps)
    typer.echo("\nAll steps passed!" if all_ok else "\nSome steps failed.")


@app.command()
def status(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Show WHOIS8 server status."""
    s = _get_server()
    d = s.summary()
    if as_json:
        typer.echo(json.dumps(d))
    else:
        typer.echo(f"Server:  {d['server_id']}")
        typer.echo(f"ASNs:    {d['registered_asns']}")
        typer.echo(f"Routes:  {d['registered_routes']}")
        typer.echo(f"Queries: {d['queries_served']}")
        typer.echo(f"Signing: {d['signing_enabled']}")
