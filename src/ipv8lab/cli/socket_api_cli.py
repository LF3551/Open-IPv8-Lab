# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""CLI for Socket API Compatibility mock per Section 6.2."""

from __future__ import annotations

import json

import typer

from ipv8lab.address import IPv8Address
from ipv8lab.socket_api import (
    AF_INET,
    AF_INET8,
    CompatLayer,
    SockaddrIn8,
    SocketType,
    create_socket,
)

app = typer.Typer(no_args_is_help=True)


@app.command()
def info(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Show AF_INET8 and sockaddr_in8 definition."""
    fields = [
        {"name": "sin8_family", "type": "sa_family_t", "description": "AF_INET8"},
        {"name": "sin8_port", "type": "in_port_t", "description": "port number"},
        {"name": "sin8_rn", "type": "uint32_t", "description": "Routing Number (RN)"},
        {"name": "sin8_addr", "type": "struct in_addr", "description": "n.n.n.n host address"},
    ]
    data: dict[str, object] = {
        "AF_INET": AF_INET,
        "AF_INET8": AF_INET8,
        "sockaddr_in8_fields": fields,
    }
    if as_json:
        typer.echo(json.dumps(data))
    else:
        typer.echo(f"AF_INET  = {AF_INET}")
        typer.echo(f"AF_INET8 = {AF_INET8}")
        typer.echo()
        typer.echo("struct sockaddr_in8 {")
        for f in fields:
            typer.echo(f"    {f['type']:<16} {f['name']:<16} /* {f['description']} */")
        typer.echo("};")


@app.command()
def create(
    address: str = typer.Argument(..., help="IPv8 address (e.g. 64496.10.0.0.1)"),
    port: int = typer.Option(0, help="Port number"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Create a sockaddr_in8 from an IPv8 address."""
    addr = IPv8Address.parse(address)
    sa8 = SockaddrIn8.from_ipv8_address(addr, port=port)
    if as_json:
        typer.echo(json.dumps(sa8.to_dict()))
    else:
        typer.echo(f"sin8_family = {sa8.sin8_family} (AF_INET8)")
        typer.echo(f"sin8_port   = {sa8.sin8_port}")
        typer.echo(f"sin8_rn     = {sa8.sin8_rn}")
        typer.echo(f"sin8_addr   = {sa8.sin8_addr}")


@app.command()
def upgrade(
    host: str = typer.Argument(..., help="IPv4 host address"),
    port: int = typer.Option(80, help="Port number"),
    asn: int = typer.Option(0, help="Default ASN for compat layer"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Upgrade a legacy (host, port) to sockaddr_in8 via compat layer."""
    compat = CompatLayer(default_asn=asn)
    sa8 = compat.upgrade_connect((host, port))
    if as_json:
        typer.echo(json.dumps(sa8.to_dict()))
    else:
        typer.echo(f"Legacy:   ({host}, {port})")
        typer.echo(f"Upgraded: sin8_rn={sa8.sin8_rn} sin8_addr={sa8.sin8_addr} sin8_port={sa8.sin8_port}")


@app.command()
def simulate(
    src: str = typer.Argument(..., help="Source IPv8 address"),
    dst: str = typer.Argument(..., help="Destination IPv8 address"),
    port: int = typer.Option(443, help="Destination port"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Simulate a socket connect/send/close cycle."""
    src_addr = IPv8Address.parse(src)
    dst_addr = IPv8Address.parse(dst)

    sock = create_socket(family=AF_INET8, default_asn=src_addr.asn)

    sa_local = SockaddrIn8.from_ipv8_address(src_addr, port=0)
    sa_remote = SockaddrIn8.from_ipv8_address(dst_addr, port=port)

    sock.bind(sa_local)
    sock.connect(sa_remote)
    sock.send(b"GET / HTTP/1.1\r\n\r\n")
    sock.recv()
    sock.close()

    events = [
        {
            "action": e.action,
            "family": e.family,
            "address": e.address.to_dict() if isinstance(e.address, SockaddrIn8) else None,
        }
        for e in sock.events
    ]
    if as_json:
        typer.echo(json.dumps(events))
    else:
        for e in sock.events:
            addr_s = ""
            if e.address and isinstance(e.address, SockaddrIn8):
                addr_s = f" → {e.address.sin8_rn}.{e.address.sin8_addr}:{e.address.sin8_port}"
            typer.echo(f"  {e.action:<10}{addr_s}")


@app.command()
def status(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Show Socket API module status."""
    data = {
        "module": "socket_api",
        "spec": "draft-thain-ipv8 Section 6",
        "AF_INET8": AF_INET8,
        "sock_types": [t.name for t in SocketType],
    }
    if as_json:
        typer.echo(json.dumps(data))
    else:
        typer.echo(f"Module: {data['module']}")
        typer.echo(f"Spec:   {data['spec']}")
        typer.echo(f"AF_INET8 = {AF_INET8}")
