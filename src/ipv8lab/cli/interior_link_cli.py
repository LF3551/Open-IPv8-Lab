# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""CLI for Interior Link Convention per draft-thain-ipv8- Section 4.10."""

from __future__ import annotations

import json

import typer

from ipv8lab.address import IPv8Address
from ipv8lab.interior_link import (
    check_interior_link_egress,
    is_interior_link_address,
    make_interior_links,
    summarize_interior_links,
    validate_interior_link,
)

app = typer.Typer(no_args_is_help=True)


@app.command()
def generate(
    asn: int = typer.Argument(..., help="ASN to generate interior links for"),
    count: int = typer.Option(1, help="Number of link pairs to generate"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Generate interior link /31 pairs for an ASN."""
    links = make_interior_links(asn, count)
    if as_json:
        typer.echo(json.dumps([
            {
                "link_id": lk.link_id,
                "label": lk.label,
                "side_a": lk.side_a.full_notation,
                "side_b": lk.side_b.full_notation,
            }
            for lk in links
        ]))
    else:
        for lk in links:
            typer.echo(f"Link {lk.link_id}: {lk.side_a.full_notation} ↔ {lk.side_b.full_notation}")


@app.command(name="validate")
def validate_cmd(
    address: str = typer.Argument(..., help="IPv8 address to validate"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Validate an address against interior link convention rules."""
    addr = IPv8Address.parse(address)
    violations = validate_interior_link(addr)
    is_il = is_interior_link_address(addr)
    d = {"address": address, "is_interior_link": is_il, "violations": violations}
    if as_json:
        typer.echo(json.dumps(d))
    else:
        typer.echo(f"{address}: {'interior link' if is_il else 'not interior link'}")
        if violations:
            for v in violations:
                typer.echo(f"  VIOLATION: {v}")
        elif is_il:
            typer.echo("  OK — valid interior link address")


@app.command()
def check(
    address: str = typer.Argument(..., help="Address to check for egress violation"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Check if an interior link address would violate egress rules."""
    addr = IPv8Address.parse(address)
    violation = check_interior_link_egress(addr)
    d = {"address": address, "egress_violation": violation}
    if as_json:
        typer.echo(json.dumps(d))
    else:
        if violation:
            typer.echo(f"BLOCKED: {violation}")
        else:
            typer.echo(f"{address}: not an interior link — egress OK")


@app.command()
def summary(
    asn: int = typer.Argument(..., help="ASN to summarize"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Show interior link address space summary for an ASN."""
    s = summarize_interior_links(asn)
    d = {
        "asn": s.asn,
        "asn_prefix": s.asn_prefix,
        "address_range": s.address_range,
        "max_links": s.max_links,
        "convention": s.convention,
    }
    if as_json:
        typer.echo(json.dumps(d))
    else:
        typer.echo(f"ASN:        {s.asn} ({s.asn_prefix})")
        typer.echo(f"Range:      {s.address_range}")
        typer.echo(f"Max links:  {s.max_links:,}")
        typer.echo(f"Convention: {s.convention}")
