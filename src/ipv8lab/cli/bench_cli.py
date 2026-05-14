# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""CLI command for performance benchmarks."""

import json

import typer
from rich.console import Console
from rich.table import Table

from ipv8lab.benchmark import run_all

app = typer.Typer(no_args_is_help=True)
console = Console()


@app.command("run")
def run_benchmarks(
    iterations: int = typer.Option(10_000, "--iterations", "-n", help="Iterations per benchmark."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Run performance benchmarks."""
    results = run_all(iterations)

    if as_json:
        items = [
            {
                "name": r.name,
                "iterations": r.iterations,
                "total_seconds": round(r.total_seconds, 6),
                "ops_per_second": round(r.ops_per_second, 1),
                "us_per_op": round(r.us_per_op, 2),
            }
            for r in results
        ]
        console.print(json.dumps(items, indent=2))
        return

    table = Table(title=f"IPv8 Lab Benchmarks ({iterations} iterations)")
    table.add_column("Benchmark", style="bold cyan")
    table.add_column("Total (s)", justify="right")
    table.add_column("µs/op", justify="right")
    table.add_column("ops/s", justify="right", style="green")

    for r in results:
        table.add_row(
            r.name,
            f"{r.total_seconds:.4f}",
            f"{r.us_per_op:.2f}",
            f"{r.ops_per_second:,.0f}",
        )
    console.print(table)
