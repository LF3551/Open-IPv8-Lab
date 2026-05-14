# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""CLI commands for packet fuzzer."""

from __future__ import annotations

import json

import typer
from rich.console import Console
from rich.table import Table

from ipv8lab.fuzzer import (
    FuzzConfig,
    FuzzStrategy,
    FuzzTarget,
    Fuzzer,
)

app = typer.Typer(no_args_is_help=True)
console = Console()

# Module-level state
_fuzzer: Fuzzer | None = None


def _reset() -> None:
    global _fuzzer
    _fuzzer = None


@app.command("run")
def cmd_run(
    count: int = typer.Option(100, "--count", "-n", help="Number of fuzz cases."),
    seed: int = typer.Option(0, "--seed", "-s", help="Random seed (0 = random)."),
    strategy: str = typer.Option("combined", "--strategy", help="Strategy: bit_flip, byte_random, boundary, truncate, extend, checksum, field_mutate, fragment, combined."),
    target: str = typer.Option("parser", "--target", "-t", help="Target: parser, security, fragment, routing, all."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Run the packet fuzzer against the parser."""
    global _fuzzer

    try:
        strat = FuzzStrategy(strategy)
    except ValueError:
        console.print(f"[red]Error:[/red] Invalid strategy '{strategy}'.")
        raise typer.Exit(1)

    try:
        tgt = FuzzTarget(target)
    except ValueError:
        console.print(f"[red]Error:[/red] Invalid target '{target}'.")
        raise typer.Exit(1)

    config = FuzzConfig(count=count, seed=seed, strategies=[strat], target=tgt)
    _fuzzer = Fuzzer(seed=seed, config=config)
    result = _fuzzer.run(count=count, target=tgt)

    if as_json:
        typer.echo(json.dumps(result.to_dict(), indent=2))
        return

    console.print("\n[bold cyan]━━━ Fuzzer Results ━━━[/bold cyan]")
    console.print(f"  Seed:         {_fuzzer.seed}")
    console.print(f"  Cases:        {result.total_cases}")
    console.print(f"  Crashes:      {result.crashes}")
    console.print(f"  Errors:       {result.errors}")
    console.print(f"  Success rate: {result.success_rate:.1%}")

    if result.findings:
        console.print(f"\n[bold]Findings ({len(result.findings)}):[/bold]")
        for f in result.findings[:10]:
            color = {"critical": "red", "high": "red", "medium": "yellow", "low": "blue", "info": "dim"}.get(f.severity.value, "white")
            console.print(f"  [{color}]{f.severity.value.upper()}[/{color}] #{f.case_id}: {f.description}")
    else:
        console.print("\n[green]✓[/green] No findings — parser handled all cases gracefully")


@app.command("generate")
def cmd_generate(
    count: int = typer.Option(10, "--count", "-n", help="Number of cases to generate."),
    seed: int = typer.Option(0, "--seed", "-s", help="Random seed."),
    strategy: str = typer.Option("combined", "--strategy", help="Fuzzing strategy."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Generate fuzz cases without running them."""
    global _fuzzer

    try:
        strat = FuzzStrategy(strategy)
    except ValueError:
        console.print(f"[red]Error:[/red] Invalid strategy '{strategy}'.")
        raise typer.Exit(1)

    config = FuzzConfig(count=count, seed=seed, strategies=[strat])
    _fuzzer = Fuzzer(seed=seed, config=config)
    result = _fuzzer.run_dry(count=count)

    if as_json:
        cases_data = [c.to_dict() for c in result.cases]
        typer.echo(json.dumps({"count": len(cases_data), "seed": _fuzzer.seed, "cases": cases_data}, indent=2))
        return

    console.print(f"[green]✓[/green] Generated {len(result.cases)} fuzz cases (seed={_fuzzer.seed})")
    for c in result.cases[:5]:
        console.print(f"  #{c.case_id}: {c.strategy.value} ({len(c.raw_bytes)} bytes) {c.mutations[0] if c.mutations else ''}")
    if len(result.cases) > 5:
        console.print(f"  ... and {len(result.cases) - 5} more")


@app.command("strategies")
def cmd_strategies(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """List available fuzzing strategies."""
    strategies = [{"id": s.value, "name": s.value.replace("_", " ").title()} for s in FuzzStrategy]

    if as_json:
        typer.echo(json.dumps({"strategies": strategies}, indent=2))
        return

    console.print("[bold]Available strategies:[/bold]")
    for s in strategies:
        console.print(f"  • {s['id']}")


@app.command("targets")
def cmd_targets(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """List available fuzz targets."""
    targets = [{"id": t.value, "name": t.value.replace("_", " ").title()} for t in FuzzTarget]

    if as_json:
        typer.echo(json.dumps({"targets": targets}, indent=2))
        return

    console.print("[bold]Available targets:[/bold]")
    for t in targets:
        console.print(f"  • {t['id']}")


@app.command("demo")
def cmd_demo(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Run a demo fuzz session with all strategies."""
    results: list[dict[str, object]] = []

    for strat in FuzzStrategy:
        if strat == FuzzStrategy.COMBINED:
            continue
        config = FuzzConfig(count=20, seed=42, strategies=[strat])
        fuzzer = Fuzzer(seed=42, config=config)
        r = fuzzer.run(count=20)
        results.append({
            "strategy": strat.value,
            "cases": r.total_cases,
            "crashes": r.crashes,
            "errors": r.errors,
            "success_rate": round(r.success_rate, 4),
        })

    # Combined
    config = FuzzConfig(count=50, seed=42, strategies=[FuzzStrategy.COMBINED])
    fuzzer = Fuzzer(seed=42, config=config)
    r = fuzzer.run(count=50)
    results.append({
        "strategy": "combined",
        "cases": r.total_cases,
        "crashes": r.crashes,
        "errors": r.errors,
        "success_rate": round(r.success_rate, 4),
    })

    if as_json:
        typer.echo(json.dumps({"demo_results": results}, indent=2))
        return

    table = Table(title="Fuzzer Demo Results", box=None)
    table.add_column("Strategy", style="cyan")
    table.add_column("Cases", justify="right")
    table.add_column("Crashes", justify="right")
    table.add_column("Errors", justify="right")
    table.add_column("Success", justify="right")
    for r_item in results:
        table.add_row(
            str(r_item["strategy"]),
            str(r_item["cases"]),
            str(r_item["crashes"]),
            str(r_item["errors"]),
            f"{float(str(r_item['success_rate'])):.1%}",
        )
    console.print(table)
    console.print("\n[green]✓[/green] Fuzzer demo complete")
