# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""CLI commands for CF performance dashboard."""

from __future__ import annotations

import json

import typer
from rich.console import Console
from rich.table import Table

from ipv8lab.cf_dashboard import CFDashboardState, create_demo_state, run_cf_dashboard
from ipv8lab.cost_factor import CFComponents

app = typer.Typer(no_args_is_help=True)
console = Console()

# Module-level state
_state: CFDashboardState | None = None


def _ensure_state() -> CFDashboardState:
    global _state
    if _state is None:
        _state = CFDashboardState()
    return _state


@app.command("init")
def init_state(
    intrazone_cf: int = typer.Option(0, "--intrazone-cf", help="Intrazone CF value."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Initialize dashboard state."""
    global _state
    _state = CFDashboardState(intrazone_cf=intrazone_cf)

    if as_json:
        typer.echo(json.dumps({"status": "initialized", "intrazone_cf": intrazone_cf}, indent=2))
        return

    console.print(f"[green]✓[/green] CF dashboard state initialized (intrazone_cf={intrazone_cf})")


@app.command("add-path")
def add_path(
    path_id: str = typer.Argument(help="Path identifier."),
    origin_asn: int = typer.Argument(help="Origin ASN."),
    as_path: str = typer.Option("", "--as-path", help="Comma-separated AS path."),
    rtt: float = typer.Option(0.0, "--rtt", help="RTT component (0.0–1.0)."),
    packet_loss: float = typer.Option(0.0, "--packet-loss", help="Packet loss (0.0–1.0)."),
    congestion: float = typer.Option(0.0, "--congestion", help="Congestion (0.0–1.0)."),
    stability: float = typer.Option(0.0, "--stability", help="Stability (0.0–1.0)."),
    capacity: float = typer.Option(0.0, "--capacity", help="Capacity (0.0–1.0)."),
    economic: float = typer.Option(0.0, "--economic", help="Economic (0.0–1.0)."),
    geographic: float = typer.Option(0.0, "--geographic", help="Geographic (0.0–1.0)."),
    hop_cfs: str = typer.Option("", "--hop-cfs", help="Comma-separated per-hop CF values."),
    distance_km: float = typer.Option(0.0, "--distance-km", help="Distance in km."),
    measured_rtt_ms: float = typer.Option(0.0, "--measured-rtt-ms", help="Measured RTT in ms."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Add a path to the dashboard."""
    state = _ensure_state()
    try:
        components = CFComponents(
            rtt=rtt, packet_loss=packet_loss, congestion=congestion,
            stability=stability, capacity=capacity, economic=economic,
            geographic=geographic,
        )
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    path_tuple = [int(a) for a in as_path.split(",") if a.strip()] if as_path else []
    cf_list = [int(c) for c in hop_cfs.split(",") if c.strip()] if hop_cfs else None

    entry = state.add_path(
        path_id=path_id, origin_asn=origin_asn, as_path=path_tuple,
        components=components, hop_cfs=cf_list,
        distance_km=distance_km, measured_rtt_ms=measured_rtt_ms,
    )

    if as_json:
        typer.echo(json.dumps(entry.to_dict(), indent=2))
        return

    console.print(f"[green]✓[/green] Path [bold]{path_id}[/bold] added (CF={entry.cf_value})")


@app.command("remove-path")
def remove_path(
    path_id: str = typer.Argument(help="Path identifier."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Remove a path from the dashboard."""
    state = _ensure_state()
    ok = state.remove_path(path_id)

    if as_json:
        typer.echo(json.dumps({"removed": ok, "path_id": path_id}, indent=2))
        return

    if ok:
        console.print(f"[green]✓[/green] Path {path_id} removed")
    else:
        console.print(f"[yellow]![/yellow] Path {path_id} not found")


@app.command("rank")
def rank_paths(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Show paths ranked by CF_total."""
    state = _ensure_state()
    ranked = state.ranked_paths()

    if as_json:
        typer.echo(json.dumps([p.to_dict() for p in ranked], indent=2))
        return

    if not ranked:
        console.print("[dim]No paths configured.[/dim]")
        return

    table = Table(title="Path Ranking (by CF_total)", box=None)
    table.add_column("#", style="bold")
    table.add_column("Path ID", style="bold cyan")
    table.add_column("Origin")
    table.add_column("AS-path")
    table.add_column("CF value")
    table.add_column("Accumulated")
    table.add_column("Anomaly")

    for i, p in enumerate(ranked, 1):
        anomaly = "[red]⚠[/red]" if p.anomaly else ""
        table.add_row(
            str(i), p.path_id, f"AS{p.origin_asn}",
            str(p.as_path), str(p.cf_value),
            str(p.accumulated_cf), anomaly,
        )
    console.print(table)


@app.command("best")
def show_best(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Show the best path (lowest CF_total)."""
    state = _ensure_state()
    best = state.best_path()

    if as_json:
        typer.echo(json.dumps(best.to_dict() if best else None, indent=2))
        return

    if best is None:
        console.print("[dim]No paths configured.[/dim]")
        return

    console.print(f"[bold green]Best path:[/bold green] {best.path_id}")
    console.print(f"  Origin: AS{best.origin_asn}")
    console.print(f"  CF: {best.cf_value} (accumulated: {best.accumulated_cf})")


@app.command("anomalies")
def show_anomalies(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Show paths with CF anomalies."""
    state = _ensure_state()
    anom = state.anomalies()

    if as_json:
        typer.echo(json.dumps([p.to_dict() for p in anom], indent=2))
        return

    if not anom:
        console.print("[green]No anomalies detected.[/green]")
        return

    table = Table(title="CF Anomalies", box=None)
    table.add_column("Path ID", style="bold red")
    table.add_column("Distance (km)")
    table.add_column("Measured RTT (ms)")
    table.add_column("Min RTT (ms)")

    from ipv8lab.cost_factor import physics_floor_ms

    for p in anom:
        min_rtt = round(2 * physics_floor_ms(p.distance_km), 2)
        table.add_row(p.path_id, str(p.distance_km), str(p.measured_rtt_ms), str(min_rtt))
    console.print(table)


@app.command("benchmarks")
def run_bench(
    iterations: int = typer.Option(1000, "--iterations", "-n", help="Iterations per benchmark."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Run performance benchmarks."""
    state = _ensure_state()
    results = state.run_benchmarks(iterations)

    if as_json:
        typer.echo(json.dumps([
            {
                "name": b.name, "iterations": b.iterations,
                "ops_per_second": round(b.ops_per_second, 1),
                "us_per_op": round(b.us_per_op, 2),
            }
            for b in results
        ], indent=2))
        return

    table = Table(title="Performance Benchmarks", box=None)
    table.add_column("Benchmark", style="bold cyan")
    table.add_column("Iterations")
    table.add_column("ops/s")
    table.add_column("μs/op")

    for b in results:
        table.add_row(b.name, str(b.iterations), f"{b.ops_per_second:,.1f}", f"{b.us_per_op:.2f}")
    console.print(table)


@app.command("status")
def show_status(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Show dashboard summary."""
    state = _ensure_state()
    data = state.summary()

    if as_json:
        typer.echo(json.dumps(data, indent=2))
        return

    table = Table(title="CF Dashboard Status", show_header=False, box=None)
    table.add_column(style="bold cyan", min_width=20)
    table.add_column()
    table.add_row("Paths", str(data["paths"]))
    table.add_row("Intrazone CF", str(data["intrazone_cf"]))
    table.add_row("Best path", str(data["best_path"] or "-"))
    table.add_row("Best CF_total", str(data["best_cf_total"]) if data["best_cf_total"] is not None else "-")
    table.add_row("Anomalies", str(data["anomalies"]))
    table.add_row("Benchmarks run", "Yes" if data["benchmarks_run"] else "No")
    console.print(table)


@app.command("serve")
def serve(
    host: str = typer.Option("127.0.0.1", help="Bind address."),
    port: int = typer.Option(8719, help="Port number."),
    demo: bool = typer.Option(False, "--demo", help="Load demo data."),
) -> None:
    """Start the CF performance dashboard web server."""
    global _state
    if demo:
        _state = create_demo_state()
        console.print("[bold green]Demo data loaded[/bold green]")
    state = _ensure_state()
    run_cf_dashboard(state, host=host, port=port)


@app.command("demo")
def run_demo(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Load demo data: 4 paths (incl. 1 anomaly)."""
    global _state
    _state = create_demo_state()
    state = _state

    if as_json:
        typer.echo(json.dumps(state.to_dict(), indent=2))
        return

    console.print("[bold]CF Dashboard Demo[/bold]")
    ranked = state.ranked_paths()
    for i, p in enumerate(ranked, 1):
        icon = "[red]⚠[/red]" if p.anomaly else "[green]✓[/green]"
        console.print(f"  #{i} {icon} {p.path_id} — CF={p.cf_value}, acc={p.accumulated_cf}")
    console.print()
    console.print(f"[bold]{state.path_count} paths, {len(state.anomalies())} anomaly(ies)[/bold]")
