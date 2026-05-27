# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""CLI for Cloud Provider VPC simulation per Section 17."""

from __future__ import annotations

import json

import typer

from ipv8lab.address import IPv8Address
from ipv8lab.cloud_vpc import CloudVPCFabric

app = typer.Typer(no_args_is_help=True)

_fabric: CloudVPCFabric | None = None


def _get_fabric() -> CloudVPCFabric:
    global _fabric
    if _fabric is None:
        _fabric = CloudVPCFabric()
    return _fabric


@app.command()
def init(
    asn: int = typer.Option(64496, help="Cloud provider ASN"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Initialise the Cloud VPC fabric."""
    global _fabric
    _fabric = CloudVPCFabric(provider_asn=asn)
    d = _fabric.summary()
    if as_json:
        typer.echo(json.dumps(d))
    else:
        typer.echo(f"Cloud VPC fabric initialised (ASN {asn})")


@app.command(name="create")
def create_vpc(
    vpc_id: str = typer.Argument(..., help="VPC identifier"),
    customer: str = typer.Option("default", help="Customer name"),
    cidr: str = typer.Option("10.0.0.0/16", help="Internal CIDR"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Create a customer VPC with a unique 127.x.x.x zone prefix."""
    fabric = _get_fabric()
    vpc = fabric.create_vpc(vpc_id=vpc_id, customer=customer, cidr=cidr)
    if as_json:
        typer.echo(json.dumps(vpc.to_dict()))
    else:
        typer.echo(f"VPC {vpc_id}: zone_prefix={vpc.zone_prefix_str} cidr={cidr}")


@app.command(name="list")
def list_vpcs(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """List all VPCs."""
    fabric = _get_fabric()
    vpcs = fabric.list_vpcs()
    if as_json:
        typer.echo(json.dumps([v.to_dict() for v in vpcs]))
    else:
        if not vpcs:
            typer.echo("No VPCs.")
        else:
            for v in vpcs:
                typer.echo(f"  {v.vpc_id:<15} {v.zone_prefix_str:<15} {v.customer}")


@app.command()
def peer(
    vpc_a: str = typer.Argument(..., help="First VPC"),
    vpc_b: str = typer.Argument(..., help="Second VPC"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Create a peering link between two VPCs."""
    fabric = _get_fabric()
    p = fabric.create_peering(vpc_a, vpc_b)
    if as_json:
        typer.echo(json.dumps(p.to_dict()))
    else:
        typer.echo(f"Peering: {vpc_a} ↔ {vpc_b}")


@app.command()
def resolve(
    address: str = typer.Argument(..., help="IPv8 address to resolve"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Resolve which VPC an address belongs to."""
    fabric = _get_fabric()
    addr = IPv8Address.parse(address)
    vpc = fabric.resolve_vpc(addr)
    if as_json:
        typer.echo(json.dumps(vpc.to_dict() if vpc else None))
    else:
        if vpc:
            typer.echo(f"{addr.canonical} → VPC {vpc.vpc_id} ({vpc.customer})")
        else:
            typer.echo(f"{addr.canonical} → no matching VPC")


@app.command()
def check(
    src: str = typer.Argument(..., help="Source IPv8 address"),
    dst: str = typer.Argument(..., help="Destination IPv8 address"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Check if src can reach dst (same VPC or peered)."""
    fabric = _get_fabric()
    s = IPv8Address.parse(src)
    d_addr = IPv8Address.parse(dst)
    ok = fabric.can_communicate(s, d_addr)
    if as_json:
        typer.echo(json.dumps({"src": s.canonical, "dst": d_addr.canonical, "reachable": ok}))
    else:
        status = "reachable" if ok else "NOT reachable"
        typer.echo(f"{s.canonical} → {d_addr.canonical}: {status}")


@app.command()
def validate(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Validate no zone prefix overlap between VPCs."""
    fabric = _get_fabric()
    issues = fabric.validate_no_overlap()
    if as_json:
        typer.echo(json.dumps({"issues": issues, "ok": len(issues) == 0}))
    else:
        if not issues:
            typer.echo("OK — no zone prefix overlap")
        else:
            for issue in issues:
                typer.echo(f"  OVERLAP: {issue}")


@app.command()
def status(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Show Cloud VPC fabric status."""
    fabric = _get_fabric()
    d = fabric.summary()
    if as_json:
        typer.echo(json.dumps(d))
    else:
        typer.echo(f"ASN:      {d['provider_asn']}")
        typer.echo(f"VPCs:     {d['vpc_count']}")
        typer.echo(f"Peerings: {d['peering_count']}")
