# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Interactive CLI for Zone Server management."""

from __future__ import annotations

import json

import typer
from rich.console import Console
from rich.table import Table

from ipv8lab.zoneserver import (
    ACL8Action,
    ACL8Rule,
    ZoneServer,
    ZoneService,
    ZoneServiceType,
    make_zone_server_pair,
)

app = typer.Typer(no_args_is_help=True)
console = Console()

# Module-level state for the interactive session
_primary: ZoneServer | None = None
_secondary: ZoneServer | None = None
_zone_prefix: str = ""


def _ensure_pair() -> tuple[ZoneServer, ZoneServer]:
    """Return the active Zone Server pair, creating if needed."""
    global _primary, _secondary, _zone_prefix
    if _primary is None or _secondary is None:
        _primary, _secondary = make_zone_server_pair(_zone_prefix)
    return _primary, _secondary


def _get_server(role: str) -> ZoneServer:
    """Get server by role string."""
    primary, secondary = _ensure_pair()
    if role.lower() in ("primary", "p", "pri"):
        return primary
    if role.lower() in ("secondary", "s", "sec"):
        return secondary
    console.print(f"[red]Unknown role:[/red] {role}. Use 'primary' or 'secondary'.")
    raise typer.Exit(1)


@app.command("init")
def init_zone(
    prefix: str = typer.Option("127.1.0.0", help="Zone prefix (e.g. 127.1.0.0)."),
    key_id: str = typer.Option("default-key", help="OAuth8 key ID to register."),
    secret: str = typer.Option("default-secret", help="OAuth8 shared secret."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Initialize a Zone Server pair for a zone."""
    global _primary, _secondary, _zone_prefix
    _zone_prefix = prefix
    _primary, _secondary = make_zone_server_pair(prefix)

    # Register OAuth8 keys on both servers
    _primary.oauth8_cache.register_key(key_id, secret.encode())
    _secondary.oauth8_cache.register_key(key_id, secret.encode())

    if as_json:
        typer.echo(json.dumps({
            "zone_prefix": prefix,
            "primary": {"role": "PRIMARY", "host_octet": 254},
            "secondary": {"role": "SECONDARY", "host_octet": 253},
            "oauth8_key_id": key_id,
        }, indent=2))
        return

    table = Table(title=f"Zone Server Pair — {prefix}", show_header=False, box=None)
    table.add_column(style="bold cyan", min_width=20)
    table.add_column()
    table.add_row("Zone prefix", prefix)
    table.add_row("Primary (.254)", f"{prefix}.*.*.*.254")
    table.add_row("Secondary (.253)", f"{prefix}.*.*.*.253")
    table.add_row("OAuth8 key", key_id)
    table.add_row("Status", "[green]Active[/green]")
    console.print(table)


@app.command("status")
def show_status(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Show Zone Server pair status."""
    primary, secondary = _ensure_pair()

    if as_json:
        typer.echo(json.dumps({
            "zone_prefix": _zone_prefix,
            "primary": {
                "role": "PRIMARY",
                "services": primary.service_count,
                "oauth8_keys": primary.oauth8_cache.key_count,
                "acl8_rules": primary.acl8_engine.rule_count,
            },
            "secondary": {
                "role": "SECONDARY",
                "services": secondary.service_count,
                "oauth8_keys": secondary.oauth8_cache.key_count,
                "acl8_rules": secondary.acl8_engine.rule_count,
            },
        }, indent=2))
        return

    table = Table(title="Zone Server Status", box=None)
    table.add_column("Property", style="bold cyan")
    table.add_column("Primary (.254)")
    table.add_column("Secondary (.253)")

    table.add_row("Zone prefix", _zone_prefix, _zone_prefix)
    table.add_row("Services", str(primary.service_count), str(secondary.service_count))
    table.add_row("OAuth8 keys", str(primary.oauth8_cache.key_count), str(secondary.oauth8_cache.key_count))
    table.add_row("ACL8 rules", str(primary.acl8_engine.rule_count), str(secondary.acl8_engine.rule_count))
    console.print(table)


@app.command("service-add")
def add_service(
    service_type: str = typer.Argument(help="Service type (DHCP8, DNS8, NTP8, NETLOG8, OAUTH8, WHOIS8, ACL8, XLATE8)."),
    endpoint: str = typer.Argument(help="Service endpoint address."),
    role: str = typer.Option("both", help="Target server: primary, secondary, or both."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Register a service on Zone Server(s)."""
    try:
        stype = ZoneServiceType[service_type.upper()]
    except KeyError:
        valid = ", ".join(t.name for t in ZoneServiceType)
        console.print(f"[red]Invalid service type:[/red] {service_type}. Valid: {valid}")
        raise typer.Exit(1)

    primary, secondary = _ensure_pair()
    svc = ZoneService(service_type=stype, endpoint=endpoint)
    targets: list[tuple[str, ZoneServer]] = []

    if role.lower() in ("both", "all"):
        targets = [("primary", primary), ("secondary", secondary)]
    elif role.lower() in ("primary", "p", "pri"):
        targets = [("primary", primary)]
    elif role.lower() in ("secondary", "s", "sec"):
        targets = [("secondary", secondary)]
    else:
        console.print(f"[red]Unknown role:[/red] {role}")
        raise typer.Exit(1)

    for name, server in targets:
        server.register_service(svc)

    if as_json:
        typer.echo(json.dumps({
            "service_type": stype.name,
            "endpoint": endpoint,
            "registered_on": [name for name, _ in targets],
        }, indent=2))
        return

    for name, _ in targets:
        console.print(f"[green]✓[/green] {stype.name} → {endpoint} registered on {name}")


@app.command("service-list")
def list_services(
    role: str = typer.Option("primary", help="Server to list: primary or secondary."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """List services registered on a Zone Server."""
    server = _get_server(role)
    services = server.list_services()

    if as_json:
        typer.echo(json.dumps([
            {"type": s.service_type.name, "endpoint": s.endpoint, "enabled": s.enabled}
            for s in services
        ], indent=2))
        return

    if not services:
        console.print("[dim]No services registered.[/dim]")
        return

    table = Table(title=f"Services — {role}", box=None)
    table.add_column("Type", style="bold cyan")
    table.add_column("Endpoint")
    table.add_column("Enabled")

    for svc in services:
        table.add_row(svc.service_type.name, svc.endpoint, "✓" if svc.enabled else "✗")
    console.print(table)


@app.command("acl-add")
def add_acl_rule(
    source: str = typer.Argument(help="Source identifier (address, zone, or '*')."),
    destination: str = typer.Argument(help="Destination identifier."),
    action: str = typer.Option("permit", help="Action: permit or deny."),
    description: str = typer.Option("", help="Rule description."),
    role: str = typer.Option("primary", help="Target server: primary or secondary."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Add an ACL8 rule to a Zone Server."""
    try:
        acl_action = ACL8Action[action.upper()]
    except KeyError:
        console.print(f"[red]Invalid action:[/red] {action}. Use 'permit' or 'deny'.")
        raise typer.Exit(1)

    server = _get_server(role)
    rule = ACL8Rule(
        source=source,
        destination=destination,
        action=acl_action,
        description=description,
    )
    server.acl8_engine.add_rule(rule)

    if as_json:
        typer.echo(json.dumps({
            "source": source, "destination": destination,
            "action": acl_action.name, "description": description,
            "server": role, "rule_index": server.acl8_engine.rule_count - 1,
        }, indent=2))
        return

    console.print(
        f"[green]✓[/green] ACL8 rule #{server.acl8_engine.rule_count - 1}: "
        f"{source} → {destination} [{acl_action.name}]"
    )


@app.command("acl-list")
def list_acl_rules(
    role: str = typer.Option("primary", help="Server to list: primary or secondary."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """List ACL8 rules on a Zone Server."""
    server = _get_server(role)
    rules = server.acl8_engine.list_rules()

    if as_json:
        typer.echo(json.dumps([
            {
                "index": i, "source": r.source, "destination": r.destination,
                "action": r.action.name, "description": r.description,
            }
            for i, r in enumerate(rules)
        ], indent=2))
        return

    if not rules:
        console.print("[dim]No ACL8 rules.[/dim]")
        return

    table = Table(title=f"ACL8 Rules — {role}", box=None)
    table.add_column("#", style="dim")
    table.add_column("Source", style="bold")
    table.add_column("Destination", style="bold")
    table.add_column("Action")
    table.add_column("Description")

    for i, rule in enumerate(rules):
        color = "green" if rule.action == ACL8Action.PERMIT else "red"
        table.add_row(str(i), rule.source, rule.destination, f"[{color}]{rule.action.name}[/{color}]", rule.description)
    console.print(table)


@app.command("acl-check")
def check_acl(
    source: str = typer.Argument(help="Source identifier."),
    destination: str = typer.Argument(help="Destination identifier."),
    role: str = typer.Option("primary", help="Server to check: primary or secondary."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Evaluate ACL8 for a source→destination pair."""
    server = _get_server(role)
    result = server.authorize_traffic(source, destination)

    if as_json:
        typer.echo(json.dumps({
            "source": source, "destination": destination,
            "action": result.action.name, "permitted": result.is_permitted,
            "reason": result.reason,
        }, indent=2))
        return

    if result.is_permitted:
        console.print(f"[green]PERMIT[/green] {source} → {destination}: {result.reason}")
    else:
        console.print(f"[red]DENY[/red] {source} → {destination}: {result.reason}")


@app.command("oauth-issue")
def issue_token(
    subject: str = typer.Argument(help="Token subject (device ID)."),
    key_id: str = typer.Option("default-key", help="OAuth8 key ID."),
    issuer: str = typer.Option("zoneserver", help="Token issuer."),
    audience: str = typer.Option("zone", help="Token audience."),
    duration: int = typer.Option(3600, help="Token duration in seconds."),
    role: str = typer.Option("primary", help="Server: primary or secondary."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Issue an OAuth8 JWT token."""
    server = _get_server(role)
    try:
        token = server.oauth8_cache.issue_token(
            key_id=key_id,
            subject=subject,
            issuer=issuer,
            audience=audience,
            duration=duration,
        )
    except KeyError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    if as_json:
        typer.echo(json.dumps({
            "subject": subject, "issuer": issuer, "audience": audience,
            "duration": duration, "token": token,
        }, indent=2))
        return

    console.print(f"[bold]Subject:[/bold] {subject}")
    console.print(f"[bold]Token:[/bold]   {token[:60]}...")


@app.command("oauth-validate")
def validate_token(
    token: str = typer.Argument(help="Raw JWT token string."),
    role: str = typer.Option("primary", help="Server: primary or secondary."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Validate an OAuth8 JWT token."""
    server = _get_server(role)
    result = server.authenticate_device(token)

    if as_json:
        data: dict[str, object] = {
            "status": result.status.name,
            "valid": result.is_valid,
            "reason": result.reason,
        }
        if result.token:
            data["subject"] = result.token.subject
            data["issuer"] = result.token.issuer
        typer.echo(json.dumps(data, indent=2))
        return

    if result.is_valid:
        assert result.token is not None
        console.print(f"[green]VALID[/green] — subject: {result.token.subject}, issuer: {result.token.issuer}")
    else:
        console.print(f"[red]{result.status.name}[/red] — {result.reason}")


@app.command("oauth-key-add")
def add_oauth_key(
    key_id: str = typer.Argument(help="Key ID."),
    secret: str = typer.Argument(help="Shared secret."),
    role: str = typer.Option("both", help="Target: primary, secondary, or both."),
) -> None:
    """Register an OAuth8 signing key."""
    primary, secondary = _ensure_pair()
    targets: list[tuple[str, ZoneServer]] = []

    if role.lower() in ("both", "all"):
        targets = [("primary", primary), ("secondary", secondary)]
    elif role.lower() in ("primary", "p", "pri"):
        targets = [("primary", primary)]
    elif role.lower() in ("secondary", "s", "sec"):
        targets = [("secondary", secondary)]

    for name, server in targets:
        server.oauth8_cache.register_key(key_id, secret.encode())
        console.print(f"[green]✓[/green] Key {key_id!r} registered on {name}")


@app.command("vlan-check")
def check_vlan(
    vlan_id: int = typer.Argument(help="VLAN ID to check."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Check PVRST root eligibility for a VLAN."""
    primary, secondary = _ensure_pair()
    pri_root = primary.is_root_for_vlan(vlan_id)
    sec_root = secondary.is_root_for_vlan(vlan_id)

    if as_json:
        typer.echo(json.dumps({
            "vlan_id": vlan_id,
            "primary_is_root": pri_root,
            "secondary_is_root": sec_root,
            "root": "primary" if pri_root else "secondary",
        }, indent=2))
        return

    root = "Primary (.254)" if pri_root else "Secondary (.253)"
    console.print(f"VLAN {vlan_id}: PVRST root = [bold]{root}[/bold]")
