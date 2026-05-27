# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""CLI commands for NAT8 address translation gateway."""

from __future__ import annotations

import json

import typer
from rich.console import Console
from rich.table import Table

from ipv8lab.address import IPv8Address
from ipv8lab.nat8 import NATGateway, NATMode
from ipv8lab.packet import IPv8Packet

app = typer.Typer(no_args_is_help=True)
console = Console()

# Module-level state
_gw: NATGateway | None = None


def _reset() -> None:
    global _gw
    _gw = None


def _get_gw() -> NATGateway:
    if _gw is None:
        console.print("[red]Error:[/red] Gateway not initialized. Run 'init' first.")
        raise typer.Exit(1)
    return _gw


@app.command("init")
def cmd_init(
    mode: str = typer.Option("static", "--mode", "-m", help="NAT mode: static, dynamic, pat."),
    pat_addr: str = typer.Option("", "--pat-addr", help="External address for PAT mode."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Initialize the NAT8 gateway."""
    global _gw
    try:
        nat_mode = NATMode(mode)
    except ValueError:
        console.print(f"[red]Error:[/red] Invalid mode '{mode}'. Use: static, dynamic, pat.")
        raise typer.Exit(1)

    kwargs: dict[str, object] = {"mode": nat_mode}
    if pat_addr:
        kwargs["pat_address"] = pat_addr

    _gw = NATGateway(**kwargs)  # type: ignore[arg-type]

    if as_json:
        typer.echo(json.dumps({"mode": nat_mode.value, "status": "initialized"}, indent=2))
    else:
        console.print(f"[green]✓[/green] NAT8 gateway initialized (mode={nat_mode.value})")


@app.command("add-static")
def cmd_add_static(
    internal: str = typer.Argument(help="Internal IPv8 address."),
    external: str = typer.Argument(help="External IPv8 address."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Add a static NAT mapping."""
    gw = _get_gw()
    try:
        m = gw.add_static_mapping(internal, external)
    except (ValueError, TypeError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    if as_json:
        typer.echo(json.dumps(m.to_dict(), indent=2))
    else:
        console.print(f"[green]✓[/green] Static: {internal} ↔ {external}")


@app.command("add-pool")
def cmd_add_pool(
    addr: str = typer.Argument(help="External address to add to pool."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Add an address to the dynamic NAT pool."""
    gw = _get_gw()
    try:
        gw.add_pool_address(addr)
    except (ValueError, TypeError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    if as_json:
        typer.echo(json.dumps({"added": addr, "pool_size": gw.pool_size}, indent=2))
    else:
        console.print(f"[green]✓[/green] Pool address added: {addr} (pool={gw.pool_size})")


@app.command("translate")
def cmd_translate(
    src: str = typer.Option(..., "--src", help="Source IPv8 address."),
    dst: str = typer.Option(..., "--dst", help="Destination IPv8 address."),
    direction: str = typer.Option("egress", "--dir", "-d", help="Direction: egress or ingress."),
    port: int = typer.Option(0, "--port", "-p", help="Port number (for PAT)."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Translate a packet through the NAT gateway."""
    gw = _get_gw()
    try:
        src_addr = IPv8Address.parse(src)
        dst_addr = IPv8Address.parse(dst)
    except (ValueError, TypeError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    pkt = IPv8Packet(src=src_addr, dst=dst_addr, payload=b"nat8-test")

    if direction == "egress":
        result = gw.translate_egress(pkt, src_port=port)
    elif direction == "ingress":
        result = gw.translate_ingress(pkt, dst_port=port)
    else:
        console.print(f"[red]Error:[/red] Invalid direction '{direction}'. Use: egress, ingress.")
        raise typer.Exit(1)

    if result is None:
        if as_json:
            typer.echo(json.dumps({"translated": False, "reason": "no mapping"}, indent=2))
        else:
            console.print("[yellow]✗[/yellow] No mapping — packet dropped")
        return

    if as_json:
        typer.echo(json.dumps({
            "translated": True,
            "direction": direction,
            "original_src": str(pkt.src),
            "original_dst": str(pkt.dst),
            "result_src": str(result.src),
            "result_dst": str(result.dst),
        }, indent=2))
    else:
        console.print(
            f"[green]✓[/green] {direction}: "
            f"{pkt.src}→{pkt.dst} ⇒ {result.src}→{result.dst}"
        )


@app.command("status")
def cmd_status(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Show NAT gateway status and statistics."""
    gw = _get_gw()

    if as_json:
        typer.echo(json.dumps(gw.to_dict(), indent=2))
        return

    s = gw.stats()
    console.print(f"[bold]NAT8 Gateway[/bold] (mode={gw.mode.value})")
    console.print(f"  Active mappings: {s.active_mappings}")
    console.print(f"  Egress:  {s.total_egress}")
    console.print(f"  Ingress: {s.total_ingress}")
    console.print(f"  Dropped: {s.total_dropped}")
    if gw.mode == NATMode.DYNAMIC:
        console.print(f"  Pool available: {s.pool_available}")


@app.command("mappings")
def cmd_mappings(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """List all active NAT mappings."""
    gw = _get_gw()
    mappings = gw.all_mappings()

    if as_json:
        typer.echo(json.dumps([m.to_dict() for m in mappings], indent=2))
        return

    if not mappings:
        console.print("[dim]No active mappings.[/dim]")
        return

    table = Table(box=None)
    table.add_column("Internal", style="cyan")
    table.add_column("External", style="green")
    table.add_column("Mode")
    table.add_column("Out")
    table.add_column("In")
    if gw.mode == NATMode.PAT:
        table.add_column("Int Port")
        table.add_column("Ext Port")

    for m in mappings:
        row = [
            str(m.internal_addr), str(m.external_addr),
            m.mode.value, str(m.packets_out), str(m.packets_in),
        ]
        if gw.mode == NATMode.PAT:
            row.extend([str(m.internal_port), str(m.external_port)])
        table.add_row(*row)
    console.print(table)


@app.command("release")
def cmd_release(
    internal: str = typer.Argument(help="Internal address to release."),
    port: int = typer.Option(-1, "--port", "-p", help="Port (for PAT release)."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Release a NAT mapping."""
    gw = _get_gw()
    if gw.mode == NATMode.PAT and port >= 0:
        ok = gw.release_pat(internal, port)
    else:
        ok = gw.release(internal)

    if as_json:
        typer.echo(json.dumps({"released": ok, "address": internal}, indent=2))
    else:
        if ok:
            console.print(f"[green]✓[/green] Released: {internal}")
        else:
            console.print(f"[yellow]✗[/yellow] No mapping for {internal}")


@app.command("demo")
def cmd_demo(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Run a NAT8 demo showcasing all three modes."""
    results: list[dict[str, object]] = []

    # --- Static NAT ---
    gw_s = NATGateway(mode=NATMode.STATIC)
    gw_s.add_static_mapping("127.1.0.0.10.0.1.10", "64496-10.0.1.100")
    pkt = IPv8Packet(
        src=IPv8Address.parse("127.1.0.0.10.0.1.10"),
        dst=IPv8Address.parse("64497-10.0.1.1"),
        payload=b"static-test",
    )
    out = gw_s.translate_egress(pkt)
    back = gw_s.translate_ingress(
        IPv8Packet(src=IPv8Address.parse("64497-10.0.1.1"),
                   dst=IPv8Address.parse("64496-10.0.1.100"), payload=b"reply")
    ) if out else None
    results.append({
        "mode": "static",
        "egress_src": str(out.src) if out else None,
        "ingress_dst": str(back.dst) if back else None,
        "mappings": gw_s.mapping_count,
        "stats": gw_s.stats().to_dict(),
    })

    # --- Dynamic NAT ---
    gw_d = NATGateway(mode=NATMode.DYNAMIC)
    gw_d.add_pool_address("64496-10.0.1.200")
    gw_d.add_pool_address("64496-10.0.1.201")
    hosts = ["127.1.0.0.10.0.1.20", "127.1.0.0.10.0.1.21"]
    for h in hosts:
        p = IPv8Packet(src=IPv8Address.parse(h), dst=IPv8Address.parse("64497-10.0.1.1"), payload=b"dyn")
        gw_d.translate_egress(p)
    results.append({
        "mode": "dynamic",
        "mappings": gw_d.mapping_count,
        "pool_available": gw_d.pool_available,
        "stats": gw_d.stats().to_dict(),
    })

    # --- PAT ---
    gw_p = NATGateway(mode=NATMode.PAT, pat_address="64496-10.0.1.50")
    for port in range(8080, 8085):
        p = IPv8Packet(src=IPv8Address.parse("127.1.0.0.10.0.1.30"), dst=IPv8Address.parse("64497-10.0.1.1"), payload=b"pat")
        gw_p.translate_egress(p, src_port=port)
    results.append({
        "mode": "pat",
        "mappings": gw_p.mapping_count,
        "stats": gw_p.stats().to_dict(),
    })

    if as_json:
        typer.echo(json.dumps({"scenarios": results}, indent=2))
        return

    for r in results:
        console.print(f"\n[bold cyan]━━━ {str(r['mode']).upper()} NAT ━━━[/bold cyan]")
        for k, v in r.items():
            if k == "mode":
                continue
            console.print(f"  {k}: {v}")
    console.print("\n[green]✓[/green] All NAT8 modes demonstrated")
