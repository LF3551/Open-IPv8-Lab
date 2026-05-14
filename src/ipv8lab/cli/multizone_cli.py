# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""CLI commands for multi-zone simulation."""

from __future__ import annotations

import json

import typer
from rich.console import Console
from rich.table import Table

from ipv8lab.multizone import MultiZoneSimulation, ZoneDefinition

app = typer.Typer(no_args_is_help=True)
console = Console()

# Module-level simulation state
_sim: MultiZoneSimulation | None = None


def _ensure_sim() -> MultiZoneSimulation:
    global _sim
    if _sim is None:
        _sim = MultiZoneSimulation()
    return _sim


@app.command("init")
def init_sim(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Initialize a fresh multi-zone simulation."""
    global _sim
    _sim = MultiZoneSimulation()

    if as_json:
        typer.echo(json.dumps({"status": "initialized", "zones": 0, "links": 0}, indent=2))
        return

    console.print("[green]✓[/green] Multi-zone simulation initialized")


@app.command("add-zone")
def add_zone(
    name: str = typer.Argument(help="Zone name (e.g. americas, europe, apac)."),
    octet: int = typer.Argument(help="Zone octet x in 127.x.0.0 (1–126)."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Add a zone to the simulation."""
    sim = _ensure_sim()
    try:
        dfn = ZoneDefinition(name=name, zone_octet=octet)
        inst = sim.add_zone(dfn)
    except (ValueError, TypeError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    if as_json:
        typer.echo(json.dumps({
            "name": name, "zone_prefix": inst.zone_prefix,
            "services": inst.primary.service_count,
            "total_zones": sim.zone_count,
        }, indent=2))
        return

    console.print(f"[green]✓[/green] Zone [bold]{name}[/bold] ({inst.zone_prefix}) created")


@app.command("list-zones")
def list_zones(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """List all zones in the simulation."""
    sim = _ensure_sim()
    zones = sim.list_zones()

    if as_json:
        data = []
        for zname in zones:
            z = sim.get_zone(zname)
            data.append({
                "name": zname,
                "zone_prefix": z.zone_prefix,
                "services": z.primary.service_count,
                "acl8_rules": z.primary.acl8_engine.rule_count,
                "active_leases": z.dhcp_server.active_leases,
            })
        typer.echo(json.dumps(data, indent=2))
        return

    if not zones:
        console.print("[dim]No zones configured.[/dim]")
        return

    table = Table(title="Zones", box=None)
    table.add_column("Name", style="bold cyan")
    table.add_column("Prefix")
    table.add_column("Services")
    table.add_column("ACL8 Rules")
    table.add_column("Leases")

    for zname in zones:
        z = sim.get_zone(zname)
        table.add_row(
            zname, z.zone_prefix,
            str(z.primary.service_count),
            str(z.primary.acl8_engine.rule_count),
            str(z.dhcp_server.active_leases),
        )
    console.print(table)


@app.command("connect")
def connect_zones(
    zone_a: str = typer.Argument(help="First zone name."),
    zone_b: str = typer.Argument(help="Second zone name."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Create a bidirectional IBGP8 link between two zones."""
    sim = _ensure_sim()
    try:
        link_ab, link_ba = sim.connect_zones(zone_a, zone_b)
    except KeyError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    if as_json:
        typer.echo(json.dumps({
            "link_a_b": {"source": link_ab.source_zone, "target": link_ab.target_zone, "interface": link_ab.interface},
            "link_b_a": {"source": link_ba.source_zone, "target": link_ba.target_zone, "interface": link_ba.interface},
            "total_links": sim.link_count,
        }, indent=2))
        return

    console.print(f"[green]✓[/green] {zone_a} ↔ {zone_b} via {link_ab.interface}")


@app.command("provision")
def provision_device(
    zone: str = typer.Argument(help="Zone name."),
    client_id: str = typer.Argument(help="Client/device ID."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Provision a device in a zone via DHCP8."""
    sim = _ensure_sim()
    try:
        lease = sim.provision_device(zone, client_id)
    except KeyError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    if lease is None:
        if as_json:
            typer.echo(json.dumps({"zone": zone, "client_id": client_id, "success": False, "reason": "pool exhausted"}, indent=2))
        else:
            console.print(f"[red]✗[/red] Pool exhausted for {client_id} in {zone}")
        raise typer.Exit(1)

    if as_json:
        typer.echo(json.dumps({
            "zone": zone, "client_id": client_id,
            "address": str(lease.address), "success": True,
        }, indent=2))
        return

    console.print(f"[green]✓[/green] {client_id} → {lease.address} in [bold]{zone}[/bold]")


@app.command("authenticate")
def authenticate_device(
    zone: str = typer.Argument(help="Zone name."),
    client_id: str = typer.Argument(help="Client/device ID."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Authenticate a device via OAuth8 in its zone."""
    sim = _ensure_sim()
    try:
        ok = sim.authenticate_device(zone, client_id)
    except KeyError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    if as_json:
        typer.echo(json.dumps({"zone": zone, "client_id": client_id, "authenticated": ok}, indent=2))
        return

    if ok:
        console.print(f"[green]✓[/green] {client_id} authenticated in {zone}")
    else:
        console.print(f"[red]✗[/red] {client_id} authentication failed in {zone}")


@app.command("route")
def route_between(
    src_zone: str = typer.Argument(help="Source zone name."),
    dst_zone: str = typer.Argument(help="Destination zone name."),
    src_device: str = typer.Argument(help="Source device client ID."),
    dst_device: str = typer.Argument(help="Destination device client ID."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Route a packet between devices in different zones."""
    sim = _ensure_sim()
    try:
        src_z = sim.get_zone(src_zone)
        dst_z = sim.get_zone(dst_zone)
    except KeyError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    src_lease = src_z.dhcp_server.get_lease(src_device)
    dst_lease = dst_z.dhcp_server.get_lease(dst_device)

    if src_lease is None:
        console.print(f"[red]Error:[/red] no lease for {src_device} in {src_zone}")
        raise typer.Exit(1)
    if dst_lease is None:
        console.print(f"[red]Error:[/red] no lease for {dst_device} in {dst_zone}")
        raise typer.Exit(1)

    ok = sim.route_between_zones(src_zone, dst_zone, src_lease.address, dst_lease.address)

    if as_json:
        typer.echo(json.dumps({
            "src_zone": src_zone, "dst_zone": dst_zone,
            "src_addr": str(src_lease.address), "dst_addr": str(dst_lease.address),
            "routed": ok,
        }, indent=2))
        return

    if ok:
        console.print(f"[green]✓[/green] {src_lease.address} → {dst_lease.address} routed")
    else:
        console.print(f"[red]✗[/red] No route from {src_zone} to {dst_zone}")


@app.command("acl-check")
def acl_check(
    zone: str = typer.Argument(help="Zone name."),
    source: str = typer.Argument(help="Source identifier."),
    destination: str = typer.Argument(help="Destination identifier."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Check ACL8 cross-zone traffic authorization."""
    sim = _ensure_sim()
    try:
        ok = sim.authorize_cross_zone(zone, source, destination)
    except KeyError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    if as_json:
        typer.echo(json.dumps({
            "zone": zone, "source": source, "destination": destination,
            "permitted": ok,
        }, indent=2))
        return

    if ok:
        console.print(f"[green]PERMIT[/green] {source} → {destination} in {zone}")
    else:
        console.print(f"[red]DENY[/red] {source} → {destination} in {zone}")


@app.command("events")
def show_events(
    zone: str = typer.Option("", help="Filter by zone name (empty = all)."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Show simulation events."""
    sim = _ensure_sim()
    events = sim.events
    if zone:
        events = [e for e in events if e.zone == zone]

    if as_json:
        typer.echo(json.dumps([
            {"zone": e.zone, "event": e.event, "success": e.success, "detail": e.detail}
            for e in events
        ], indent=2))
        return

    if not events:
        console.print("[dim]No events recorded.[/dim]")
        return

    table = Table(title="Simulation Events", box=None)
    table.add_column("Zone", style="bold cyan")
    table.add_column("Event")
    table.add_column("Status")
    table.add_column("Detail")

    for evt in events:
        status = "[green]✓[/green]" if evt.success else "[red]✗[/red]"
        table.add_row(evt.zone, evt.event, status, evt.detail)
    console.print(table)


@app.command("status")
def show_status(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Show overall simulation status."""
    sim = _ensure_sim()

    data = {
        "zones": sim.zone_count,
        "links": sim.link_count,
        "events": len(sim.events),
        "all_passed": sim.all_events_passed,
        "failed": len(sim.failed_events),
    }

    if as_json:
        typer.echo(json.dumps(data, indent=2))
        return

    table = Table(title="Multi-zone Simulation Status", show_header=False, box=None)
    table.add_column(style="bold cyan", min_width=20)
    table.add_column()

    table.add_row("Zones", str(data["zones"]))
    table.add_row("Links", str(data["links"]))
    table.add_row("Events", str(data["events"]))
    passed_str = "[green]Yes[/green]" if data["all_passed"] else f"[red]No ({data['failed']} failed)[/red]"
    table.add_row("All passed", passed_str)
    console.print(table)


@app.command("demo")
def run_demo(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Run a 3-zone mesh demo (Americas, Europe, APAC)."""
    global _sim
    _sim = MultiZoneSimulation()
    sim = _sim

    # Create zones
    sim.add_zone(ZoneDefinition(name="americas", zone_octet=1))
    sim.add_zone(ZoneDefinition(name="europe", zone_octet=2))
    sim.add_zone(ZoneDefinition(name="apac", zone_octet=3))

    # Full mesh
    sim.connect_zones("americas", "europe")
    sim.connect_zones("europe", "apac")
    sim.connect_zones("americas", "apac")

    # Provision
    sim.provision_device("americas", "dev-am")
    sim.provision_device("europe", "dev-eu")
    sim.provision_device("apac", "dev-ap")

    # Authenticate
    sim.authenticate_device("americas", "dev-am")
    sim.authenticate_device("europe", "dev-eu")
    sim.authenticate_device("apac", "dev-ap")

    # Route: americas → europe
    la = sim.get_zone("americas").dhcp_server.get_lease("dev-am")
    le = sim.get_zone("europe").dhcp_server.get_lease("dev-eu")
    lap = sim.get_zone("apac").dhcp_server.get_lease("dev-ap")
    assert la and le and lap

    sim.route_between_zones("americas", "europe", la.address, le.address)
    sim.route_between_zones("europe", "apac", le.address, lap.address)
    sim.route_between_zones("americas", "apac", la.address, lap.address)

    if as_json:
        typer.echo(json.dumps({
            "zones": sim.list_zones(),
            "links": sim.link_count,
            "events": len(sim.events),
            "all_passed": sim.all_events_passed,
            "failed": len(sim.failed_events),
        }, indent=2))
        return

    console.print("[bold]3-Zone Mesh Demo[/bold]")
    console.print()
    for evt in sim.events:
        icon = "[green]✓[/green]" if evt.success else "[red]✗[/red]"
        console.print(f"  {icon} [{evt.zone}] {evt.event}: {evt.detail}")
    console.print()
    if sim.all_events_passed:
        console.print("[green bold]All steps passed![/green bold]")
    else:
        console.print(f"[red bold]{len(sim.failed_events)} step(s) failed[/red bold]")
