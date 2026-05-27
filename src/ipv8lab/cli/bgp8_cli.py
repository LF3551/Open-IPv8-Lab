# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""CLI commands for BGP8 path selection with CF metric."""

from __future__ import annotations

import json
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from ipv8lab.bgp8_selection import BGP8PathSelector, build_advertisement
from ipv8lab.companions import BGP8Peer
from ipv8lab.cost_factor import CFComponents

app = typer.Typer(no_args_is_help=True)
console = Console()

# Module-level selector state
_selector: BGP8PathSelector | None = None


def _ensure_selector() -> BGP8PathSelector:
    global _selector
    if _selector is None:
        _selector = BGP8PathSelector(local_asn=64496)
    return _selector


@app.command("init")
def init_selector(
    asn: int = typer.Option(64496, "--asn", help="Local ASN."),
    intrazone_cf: int = typer.Option(0, "--intrazone-cf", help="Intrazone CF value."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Initialize a BGP8 path selector."""
    global _selector
    _selector = BGP8PathSelector(local_asn=asn)
    _selector.intrazone_cf = intrazone_cf

    if as_json:
        typer.echo(json.dumps({
            "status": "initialized",
            "local_asn": asn,
            "intrazone_cf": _selector.intrazone_cf,
        }, indent=2))
        return

    console.print(f"[green]✓[/green] BGP8 selector initialized (ASN {asn})")


@app.command("add-peer")
def add_peer(
    asn: int = typer.Argument(help="Peer ASN."),
    address: str = typer.Argument(help="Peer IPv8 address string."),
    ebgp: bool = typer.Option(True, "--ebgp/--ibgp", help="eBGP8 or iBGP8."),
    description: str = typer.Option("", "--desc", help="Peer description."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Register a BGP8 peer."""
    sel = _ensure_selector()
    peer = BGP8Peer(asn=asn, address=address, is_ebgp=ebgp, description=description)
    sel.add_peer(peer)

    if as_json:
        typer.echo(json.dumps({
            "asn": asn, "address": address, "is_ebgp": ebgp,
            "description": description, "total_peers": sel.peer_count,
        }, indent=2))
        return

    kind = "eBGP8" if ebgp else "iBGP8"
    console.print(f"[green]✓[/green] Peer AS{asn} ({kind}) added")


@app.command("advertise")
def advertise(
    prefix: str = typer.Argument(help="Prefix as IPv8 address (e.g. 64496-10.0.0.0)."),
    origin_asn: int = typer.Argument(help="Origin ASN."),
    as_path: str = typer.Option("", "--as-path", help="Comma-separated AS path (e.g. 64497,64498)."),
    next_hop: str = typer.Option("", "--next-hop", help="Next hop address."),
    prefix_length: int = typer.Option(8, "--prefix-len", help="Prefix length."),
    hop_cfs: str = typer.Option("", "--hop-cfs", help="Comma-separated per-hop CF values."),
    rtt: float = typer.Option(0.0, "--rtt", help="CF rtt component (0.0–1.0)."),
    packet_loss: float = typer.Option(0.0, "--packet-loss", help="CF packet_loss (0.0–1.0)."),
    congestion: float = typer.Option(0.0, "--congestion", help="CF congestion (0.0–1.0)."),
    stability: float = typer.Option(0.0, "--stability", help="CF stability (0.0–1.0)."),
    capacity: float = typer.Option(0.0, "--capacity", help="CF capacity (0.0–1.0)."),
    economic: float = typer.Option(0.0, "--economic", help="CF economic (0.0–1.0)."),
    geographic: float = typer.Option(0.0, "--geographic", help="CF geographic (0.0–1.0)."),
    distance_km: float = typer.Option(0.0, "--distance-km", help="Physical distance in km."),
    measured_rtt_ms: float = typer.Option(0.0, "--measured-rtt-ms", help="Measured RTT in ms."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Receive a BGP8 advertisement into the RIB."""
    sel = _ensure_selector()

    path_tuple = tuple(int(a) for a in as_path.split(",") if a.strip()) if as_path else ()
    cf_tuple = tuple(int(c) for c in hop_cfs.split(",") if c.strip()) if hop_cfs else ()

    has_cf_components = any([rtt, packet_loss, congestion, stability, capacity, economic, geographic])
    cf_comp: Optional[CFComponents] = None
    if has_cf_components:
        try:
            cf_comp = CFComponents(
                rtt=rtt, packet_loss=packet_loss, congestion=congestion,
                stability=stability, capacity=capacity, economic=economic,
                geographic=geographic,
            )
        except ValueError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(1)

    adv, cf_value = build_advertisement(
        prefix=prefix, origin_asn=origin_asn, as_path=path_tuple,
        next_hop=next_hop, cf_components=cf_comp, prefix_length=prefix_length,
    )

    final_hop_cfs = cf_tuple if cf_tuple else ((cf_value,) if cf_value else ())

    ok = sel.receive_advertisement(
        adv, hop_cfs=final_hop_cfs,
        distance_km=distance_km, measured_rtt_ms=measured_rtt_ms,
    )

    if as_json:
        typer.echo(json.dumps({
            "accepted": ok, "prefix": prefix, "origin_asn": origin_asn,
            "as_path": list(path_tuple), "cf_value": cf_value,
            "hop_cfs": list(final_hop_cfs),
            "rib_size": sel.rib_size(),
        }, indent=2))
        return

    if ok:
        console.print(f"[green]✓[/green] Advertisement accepted: {prefix} from AS{origin_asn}")
    else:
        console.print(f"[red]✗[/red] Advertisement rejected: {prefix} from AS{origin_asn}")


@app.command("withdraw")
def withdraw(
    prefix: str = typer.Argument(help="Prefix to withdraw."),
    origin_asn: int = typer.Argument(help="Origin ASN to withdraw."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Withdraw routes from a specific origin ASN."""
    sel = _ensure_selector()
    ok = sel.withdraw(prefix, origin_asn)

    if as_json:
        typer.echo(json.dumps({
            "withdrawn": ok, "prefix": prefix, "origin_asn": origin_asn,
            "rib_size": sel.rib_size(),
        }, indent=2))
        return

    if ok:
        console.print(f"[green]✓[/green] Withdrawn: {prefix} from AS{origin_asn}")
    else:
        console.print(f"[yellow]![/yellow] Nothing to withdraw: {prefix} from AS{origin_asn}")


@app.command("select")
def select_best(
    prefix: str = typer.Argument(help="Prefix to select best path for."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Run BGP8 path selection for a prefix."""
    sel = _ensure_selector()
    result = sel.select(prefix)

    if as_json:
        data: dict[str, object] = {
            "prefix": prefix,
            "reason": result.reason,
            "has_anomalies": result.has_anomalies,
            "candidates": len(result.candidates),
            "rejected": len(result.rejected),
        }
        if result.best:
            data["best"] = {
                "origin_asn": result.best.advertisement.origin_asn,
                "as_path": list(result.best.advertisement.as_path),
                "accumulated_cf": result.best.accumulated_cf,
                "as_path_length": result.best.as_path_length,
                "anomaly": result.best.anomaly,
            }
        else:
            data["best"] = None
        typer.echo(json.dumps(data, indent=2))
        return

    if result.best is None:
        console.print(f"[yellow]No path for {prefix}:[/yellow] {result.reason}")
        return

    console.print(f"[bold]Best path for {prefix}:[/bold]")
    b = result.best
    console.print(f"  Origin: AS{b.advertisement.origin_asn}")
    console.print(f"  AS-path: {list(b.advertisement.as_path)}")
    console.print(f"  Accumulated CF: {b.accumulated_cf}")
    if b.anomaly:
        console.print("  [red]⚠ CF anomaly detected[/red]")


@app.command("rib")
def show_rib(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Show the full RIB (Routing Information Base)."""
    sel = _ensure_selector()
    prefixes = sel.known_prefixes()

    if as_json:
        data = []
        for p in prefixes:
            result = sel.select(p)
            entry: dict[str, object] = {
                "prefix": p,
                "candidates": sel.candidate_count(p),
                "best_origin_asn": result.best.advertisement.origin_asn if result.best else None,
                "best_cf": result.best.accumulated_cf if result.best else None,
            }
            data.append(entry)
        typer.echo(json.dumps(data, indent=2))
        return

    if not prefixes:
        console.print("[dim]RIB is empty.[/dim]")
        return

    table = Table(title="BGP8 RIB", box=None)
    table.add_column("Prefix", style="bold cyan")
    table.add_column("Candidates")
    table.add_column("Best Origin")
    table.add_column("Best CF")

    for p in prefixes:
        result = sel.select(p)
        best_origin = f"AS{result.best.advertisement.origin_asn}" if result.best else "-"
        best_cf = str(result.best.accumulated_cf) if result.best else "-"
        table.add_row(p, str(sel.candidate_count(p)), best_origin, best_cf)
    console.print(table)


@app.command("peers")
def show_peers(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Show registered BGP8 peers."""
    sel = _ensure_selector()

    if as_json:
        data = []
        for asn in sorted(sel._peers):
            peer = sel._peers[asn]
            data.append({
                "asn": peer.asn, "address": peer.address,
                "is_ebgp": peer.is_ebgp, "description": peer.description,
            })
        typer.echo(json.dumps(data, indent=2))
        return

    if not sel._peers:
        console.print("[dim]No peers registered.[/dim]")
        return

    table = Table(title="BGP8 Peers", box=None)
    table.add_column("ASN", style="bold cyan")
    table.add_column("Address")
    table.add_column("Type")
    table.add_column("Description")

    for asn in sorted(sel._peers):
        peer = sel._peers[asn]
        table.add_row(
            f"AS{peer.asn}", peer.address,
            "eBGP8" if peer.is_ebgp else "iBGP8",
            peer.description or "-",
        )
    console.print(table)


@app.command("status")
def show_status(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Show selector status."""
    sel = _ensure_selector()

    data = {
        "local_asn": sel.local_asn,
        "intrazone_cf": sel.intrazone_cf,
        "peers": sel.peer_count,
        "prefixes": len(sel.known_prefixes()),
        "rib_size": sel.rib_size(),
    }

    if as_json:
        typer.echo(json.dumps(data, indent=2))
        return

    table = Table(title="BGP8 Selector Status", show_header=False, box=None)
    table.add_column(style="bold cyan", min_width=20)
    table.add_column()
    table.add_row("Local ASN", str(data["local_asn"]))
    table.add_row("Intrazone CF", str(data["intrazone_cf"]))
    table.add_row("Peers", str(data["peers"]))
    table.add_row("Prefixes", str(data["prefixes"]))
    table.add_row("RIB size", str(data["rib_size"]))
    console.print(table)


@app.command("demo")
def run_demo(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Run a demo: 3 peers, 2 prefixes, path selection."""
    global _selector
    _selector = BGP8PathSelector(local_asn=64496)
    sel = _selector

    # Peers
    sel.add_peer(BGP8Peer(asn=64497, address="64497-10.0.1.1"))
    sel.add_peer(BGP8Peer(asn=64498, address="64498-10.0.1.1"))
    sel.add_peer(BGP8Peer(asn=64499, address="64499-10.0.1.1"))

    # Prefix 1: 64497-0.0.0.0/8 — two paths via 64497 and 64498
    adv1, cf1 = build_advertisement(
        prefix="64497-0.0.0.0/8", origin_asn=64497,
        as_path=(64497,), next_hop="64497-10.0.1.1",
        cf_components=CFComponents(rtt=0.1, packet_loss=0.05),
        prefix_length=8,
    )
    sel.receive_advertisement(adv1, hop_cfs=(cf1,))

    adv2, cf2 = build_advertisement(
        prefix="64497-0.0.0.0/8", origin_asn=64497,
        as_path=(64498, 64497), next_hop="64498-10.0.1.1",
        cf_components=CFComponents(rtt=0.3, packet_loss=0.1),
        prefix_length=8,
    )
    sel.receive_advertisement(adv2, hop_cfs=(cf2,))

    # Prefix 2: 64499-0.0.0.0/8 — one path
    adv3, cf3 = build_advertisement(
        prefix="64499-0.0.0.0/8", origin_asn=64499,
        as_path=(64499,), next_hop="64499-10.0.1.1",
        cf_components=CFComponents(rtt=0.2, geographic=0.3),
        prefix_length=8,
    )
    sel.receive_advertisement(adv3, hop_cfs=(cf3,))

    results = sel.select_all()

    if as_json:
        data = {}
        for pfx, res in results.items():
            entry: dict[str, object] = {
                "candidates": len(res.candidates),
                "reason": res.reason,
            }
            if res.best:
                entry["best"] = {
                    "origin_asn": res.best.advertisement.origin_asn,
                    "as_path": list(res.best.advertisement.as_path),
                    "accumulated_cf": res.best.accumulated_cf,
                }
            data[pfx] = entry
        typer.echo(json.dumps({
            "local_asn": sel.local_asn,
            "peers": sel.peer_count,
            "prefixes": data,
        }, indent=2))
        return

    console.print("[bold]BGP8 Path Selection Demo[/bold]")
    console.print(f"  Local ASN: {sel.local_asn}")
    console.print(f"  Peers: {sel.peer_count}")
    console.print()
    for pfx, res in results.items():
        console.print(f"  [cyan]{pfx}[/cyan] — {len(res.candidates)} candidate(s)")
        if res.best:
            b = res.best
            console.print(f"    [green]Best:[/green] AS{b.advertisement.origin_asn} via {list(b.advertisement.as_path)}, CF={b.accumulated_cf}")
    console.print()
    console.print("[green bold]Selection complete.[/green bold]")
