# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""CLI commands for XLATE8 north-south traffic flow."""

from __future__ import annotations

import json

import typer
from rich.console import Console
from rich.table import Table

from ipv8lab.address import IPv8Address
from ipv8lab.dns_a8 import A8Record
from ipv8lab.xlate8_flow import NorthSouthFlow

app = typer.Typer(no_args_is_help=True)
console = Console()

# Module-level flow engine state
_flow: NorthSouthFlow | None = None
_counter: float = 0.0


def _clock() -> float:
    global _counter
    _counter += 1.0
    return _counter


def _ensure_flow() -> NorthSouthFlow:
    global _flow
    if _flow is None:
        _flow = NorthSouthFlow(clock=_clock)
    return _flow


@app.command("init")
def init_flow(
    zone_prefix: str = typer.Option("127.1.0.0", "--zone-prefix", help="Internal zone prefix."),
    external_asn: int = typer.Option(64496, "--external-asn", help="External ASN for translations."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Initialize XLATE8 flow engine."""
    global _flow, _counter
    _counter = 0.0
    _flow = NorthSouthFlow(zone_prefix=zone_prefix, external_asn=external_asn, clock=_clock)

    if as_json:
        typer.echo(json.dumps({
            "status": "initialized",
            "zone_prefix": zone_prefix,
            "external_asn": external_asn,
        }, indent=2))
        return

    console.print(f"[green]✓[/green] XLATE8 flow engine initialized ({zone_prefix}, ASN {external_asn})")


@app.command("dns-add")
def dns_add(
    hostname: str = typer.Argument(help="DNS hostname."),
    address: str = typer.Argument(help="IPv8 address (e.g. 64496.10.0.1.100)."),
    ttl: int = typer.Option(3600, "--ttl", help="TTL in seconds."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Add a DNS8 A8 record."""
    flow = _ensure_flow()
    try:
        addr = IPv8Address.parse(address)
    except (ValueError, TypeError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    record = A8Record(name=hostname, address=addr, ttl=ttl)
    flow.dns.add_record(record)

    if as_json:
        typer.echo(json.dumps({
            "hostname": hostname, "address": str(addr), "ttl": ttl,
            "dns_size": flow.dns.size,
        }, indent=2))
        return

    console.print(f"[green]✓[/green] DNS8: {hostname} → {addr}")


@app.command("dns-lookup")
def dns_lookup(
    hostname: str = typer.Argument(help="Hostname to resolve."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Resolve a hostname via DNS8."""
    flow = _ensure_flow()
    record = flow.dns.resolve(hostname)

    if as_json:
        if record:
            typer.echo(json.dumps({
                "hostname": hostname, "address": str(record.address),
                "ttl": record.ttl, "found": True,
            }, indent=2))
        else:
            typer.echo(json.dumps({"hostname": hostname, "found": False}, indent=2))
        return

    if record:
        console.print(f"[green]✓[/green] {hostname} → {record.address} (TTL {record.ttl})")
    else:
        console.print(f"[red]✗[/red] NXDOMAIN: {hostname}")


@app.command("egress")
def egress(
    hostname: str = typer.Argument(help="External hostname to reach."),
    internal_addr: str = typer.Argument(help="Internal device address (127.x.y.z)."),
    protocol: int = typer.Option(6, "--protocol", help="Protocol number (6=TCP)."),
    internal_port: int = typer.Option(0, "--int-port", help="Internal port."),
    external_port: int = typer.Option(0, "--ext-port", help="External port."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Run full egress flow: DNS8 → XLATE8 → translate."""
    flow = _ensure_flow()
    try:
        src = IPv8Address.parse(internal_addr)
    except (ValueError, TypeError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    pkt = flow.egress_flow(
        hostname=hostname, internal_addr=src,
        protocol=protocol, internal_port=internal_port,
        external_port=external_port,
    )

    if as_json:
        if pkt:
            typer.echo(json.dumps({
                "success": True, "hostname": hostname,
                "translated_src": str(pkt.src), "dst": str(pkt.dst),
            }, indent=2))
        else:
            typer.echo(json.dumps({"success": False, "hostname": hostname, "reason": "blocked"}, indent=2))
        return

    if pkt:
        console.print(f"[green]✓[/green] Egress: {internal_addr} → {pkt.src} (translated), dst={pkt.dst}")
    else:
        console.print(f"[red]✗[/red] Egress blocked for {hostname}")


@app.command("ingress")
def ingress(
    external_src: str = typer.Argument(help="External source address."),
    external_dst: str = typer.Argument(help="External destination (translated address)."),
    external_port: int = typer.Option(0, "--ext-port", help="External port."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Run ingress flow: reverse-translate external → internal."""
    flow = _ensure_flow()
    try:
        src = IPv8Address.parse(external_src)
        dst = IPv8Address.parse(external_dst)
    except (ValueError, TypeError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    pkt = flow.ingress_flow(external_src=src, external_dst=dst, external_port=external_port)

    if as_json:
        if pkt:
            typer.echo(json.dumps({
                "success": True, "src": str(pkt.src),
                "translated_dst": str(pkt.dst),
            }, indent=2))
        else:
            typer.echo(json.dumps({"success": False, "reason": "no reverse entry"}, indent=2))
        return

    if pkt:
        console.print(f"[green]✓[/green] Ingress: {external_dst} → {pkt.dst} (reverse-translated)")
    else:
        console.print(f"[red]✗[/red] Ingress blocked: no XLATE8 entry for {external_dst}")


@app.command("round-trip")
def round_trip(
    hostname: str = typer.Argument(help="External hostname."),
    internal_addr: str = typer.Argument(help="Internal device address."),
    protocol: int = typer.Option(6, "--protocol", help="Protocol number."),
    internal_port: int = typer.Option(0, "--int-port", help="Internal port."),
    external_port: int = typer.Option(0, "--ext-port", help="External port."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Full round-trip: egress then ingress response."""
    flow = _ensure_flow()
    try:
        src = IPv8Address.parse(internal_addr)
    except (ValueError, TypeError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    egress_pkt, ingress_pkt = flow.round_trip(
        hostname=hostname, internal_addr=src,
        protocol=protocol, internal_port=internal_port,
        external_port=external_port,
    )

    if as_json:
        data: dict[str, object] = {"hostname": hostname}
        if egress_pkt:
            data["egress"] = {"src": str(egress_pkt.src), "dst": str(egress_pkt.dst)}
        else:
            data["egress"] = None
        if ingress_pkt:
            data["ingress"] = {"src": str(ingress_pkt.src), "dst": str(ingress_pkt.dst)}
        else:
            data["ingress"] = None
        data["success"] = egress_pkt is not None and ingress_pkt is not None
        typer.echo(json.dumps(data, indent=2))
        return

    if egress_pkt and ingress_pkt:
        console.print(f"[green]✓[/green] Round-trip OK: {internal_addr} ↔ {hostname}")
        console.print(f"  Egress:  {egress_pkt.src} → {egress_pkt.dst}")
        console.print(f"  Ingress: {ingress_pkt.src} → {ingress_pkt.dst}")
    elif egress_pkt:
        console.print(f"[yellow]![/yellow] Egress OK but ingress failed for {hostname}")
    else:
        console.print(f"[red]✗[/red] Round-trip blocked for {hostname}")


@app.command("table")
def show_table(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Show the XLATE8 translation table."""
    flow = _ensure_flow()
    entries = flow.xlate_table.entries()

    if as_json:
        typer.echo(json.dumps([
            {
                "internal": e.internal_address, "external": e.external_address,
                "protocol": e.protocol,
                "internal_port": e.internal_port, "external_port": e.external_port,
                "dns_validated": e.dns_validated,
            }
            for e in entries
        ], indent=2))
        return

    if not entries:
        console.print("[dim]XLATE8 table is empty.[/dim]")
        return

    table = Table(title="XLATE8 Table", box=None)
    table.add_column("Internal", style="bold cyan")
    table.add_column("External")
    table.add_column("Proto")
    table.add_column("Int Port")
    table.add_column("Ext Port")
    table.add_column("DNS")

    for e in entries:
        table.add_row(
            e.internal_address, e.external_address,
            str(e.protocol), str(e.internal_port), str(e.external_port),
            "[green]✓[/green]" if e.dns_validated else "[red]✗[/red]",
        )
    console.print(table)


@app.command("events")
def show_events(
    direction: str = typer.Option("", help="Filter: egress, ingress, or empty for all."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Show flow events."""
    flow = _ensure_flow()
    events = flow.events
    if direction:
        events = [e for e in events if e.direction == direction]

    if as_json:
        typer.echo(json.dumps([
            {"step": e.step, "direction": e.direction, "success": e.success, "detail": e.detail}
            for e in events
        ], indent=2))
        return

    if not events:
        console.print("[dim]No events recorded.[/dim]")
        return

    table = Table(title="XLATE8 Flow Events", box=None)
    table.add_column("Step")
    table.add_column("Direction")
    table.add_column("Status")
    table.add_column("Detail")

    for evt in events:
        status = "[green]✓[/green]" if evt.success else "[red]✗[/red]"
        table.add_row(evt.step, evt.direction, status, evt.detail)
    console.print(table)


@app.command("status")
def show_status(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Show flow engine status."""
    flow = _ensure_flow()

    data = {
        "zone_prefix": flow.zone_prefix,
        "external_asn": flow.external_asn,
        "dns_records": flow.dns.size,
        "xlate_entries": len(flow.xlate_table.entries()),
        "events": len(flow.events),
        "all_passed": flow.all_events_passed,
        "failed": len(flow.failed_events),
    }

    if as_json:
        typer.echo(json.dumps(data, indent=2))
        return

    table = Table(title="XLATE8 Flow Status", show_header=False, box=None)
    table.add_column(style="bold cyan", min_width=20)
    table.add_column()
    table.add_row("Zone prefix", str(data["zone_prefix"]))
    table.add_row("External ASN", str(data["external_asn"]))
    table.add_row("DNS records", str(data["dns_records"]))
    table.add_row("XLATE entries", str(data["xlate_entries"]))
    table.add_row("Events", str(data["events"]))
    passed = "[green]Yes[/green]" if data["all_passed"] else f"[red]No ({data['failed']} failed)[/red]"
    table.add_row("All passed", passed)
    console.print(table)


@app.command("demo")
def run_demo(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Run a demo: DNS8 → egress → ingress round-trip."""
    global _flow, _counter
    _counter = 0.0
    _flow = NorthSouthFlow(zone_prefix="127.1.0.0", external_asn=64496, clock=_clock)
    flow = _flow

    # Add DNS records
    flow.dns.add_record(A8Record(name="web.example.iv8", address=IPv8Address.parse("64497.10.0.1.100")))
    flow.dns.add_record(A8Record(name="api.example.iv8", address=IPv8Address.parse("64498.10.0.2.50")))

    internal = IPv8Address.parse("127.1.0.0.10.0.1.10")

    # Round-trip 1: web.example.iv8
    eg1, ig1 = flow.round_trip(hostname="web.example.iv8", internal_addr=internal)

    # Round-trip 2: api.example.iv8
    eg2, ig2 = flow.round_trip(hostname="api.example.iv8", internal_addr=internal, internal_port=8080, external_port=443)

    # Blocked: unknown hostname
    eg3, ig3 = flow.round_trip(hostname="unknown.iv8", internal_addr=internal)

    if as_json:
        typer.echo(json.dumps({
            "trips": [
                {"hostname": "web.example.iv8", "success": eg1 is not None and ig1 is not None},
                {"hostname": "api.example.iv8", "success": eg2 is not None and ig2 is not None},
                {"hostname": "unknown.iv8", "success": eg3 is not None and ig3 is not None},
            ],
            "xlate_entries": len(flow.xlate_table.entries()),
            "events": len(flow.events),
            "all_passed": flow.all_events_passed,
            "failed": len(flow.failed_events),
        }, indent=2))
        return

    console.print("[bold]XLATE8 Flow Demo[/bold]")
    console.print()
    for evt in flow.events:
        icon = "[green]✓[/green]" if evt.success else "[red]✗[/red]"
        console.print(f"  {icon} [{evt.direction}] {evt.step}: {evt.detail}")
    console.print()
    passed = len(flow.events) - len(flow.failed_events)
    console.print(f"[bold]{passed}/{len(flow.events)} steps passed[/bold]")
