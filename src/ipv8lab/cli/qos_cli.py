# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""CLI commands for QoS traffic shaping."""

from __future__ import annotations

import json

import typer
from rich.console import Console
from rich.table import Table

from ipv8lab.address import IPv8Address
from ipv8lab.packet import IPv8Packet
from ipv8lab.qos import (
    QoSPolicy,
    TrafficClass,
    TrafficShaper,
    classify,
)

app = typer.Typer(no_args_is_help=True)
console = Console()

# Module-level state
_shaper: TrafficShaper | None = None


def _reset() -> None:
    global _shaper
    _shaper = None


def _get_shaper() -> TrafficShaper:
    if _shaper is None:
        console.print("[red]Error:[/red] Shaper not initialized. Run 'init' first.")
        raise typer.Exit(1)
    return _shaper


@app.command("init")
def cmd_init(
    policy: str = typer.Option("priority", "--policy", "-p", help="Queuing policy: priority, wfq, fifo."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Initialize the QoS traffic shaper."""
    global _shaper
    policy_map = {"priority": QoSPolicy.PRIORITY, "wfq": QoSPolicy.WFQ, "fifo": QoSPolicy.FIFO}
    qp = policy_map.get(policy.lower())
    if qp is None:
        console.print(f"[red]Error:[/red] Invalid policy '{policy}'. Use: priority, wfq, fifo.")
        raise typer.Exit(1)

    _shaper = TrafficShaper(policy=qp)

    if as_json:
        typer.echo(json.dumps({"status": "initialized", "policy": qp.name}, indent=2))
    else:
        console.print(f"[green]✓[/green] QoS shaper initialized (policy={qp.name})")


@app.command("configure")
def cmd_configure(
    tc: str = typer.Argument(help="Traffic class: EF, AF41, AF31, AF21, AF11, CS6, CS7, BE."),
    rate: int = typer.Option(0, "--rate", "-r", help="Rate limit in bps (0=unlimited)."),
    burst: int = typer.Option(0, "--burst", "-b", help="Burst size in bytes."),
    weight: int = typer.Option(1, "--weight", "-w", help="WFQ weight."),
    max_queue: int = typer.Option(1000, "--max-queue", help="Max queue depth."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Configure a traffic class queue."""
    shaper = _get_shaper()
    try:
        traffic_class = TrafficClass[tc.upper()]
    except KeyError:
        console.print(f"[red]Error:[/red] Unknown class '{tc}'. Use: {', '.join(c.name for c in TrafficClass)}")
        raise typer.Exit(1)

    shaper.configure_class(traffic_class, rate_bps=rate, burst_bytes=burst, weight=weight, max_queue=max_queue)

    if as_json:
        typer.echo(json.dumps(shaper.class_stats(traffic_class).to_dict(), indent=2))
    else:
        console.print(f"[green]✓[/green] Configured {traffic_class.name}: rate={rate}bps weight={weight}")


@app.command("classify")
def cmd_classify(
    src: str = typer.Option(..., "--src", help="Source IPv8 address."),
    dst: str = typer.Option(..., "--dst", help="Destination IPv8 address."),
    tos: int = typer.Option(0, "--tos", "-t", help="TOS field value."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Classify a packet based on TOS field."""
    try:
        src_addr = IPv8Address.parse(src)
        dst_addr = IPv8Address.parse(dst)
    except (ValueError, TypeError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    pkt = IPv8Packet(src=src_addr, dst=dst_addr, tos=tos, payload=b"qos-test")
    tc = classify(pkt)
    dscp = (tos >> 2) & 0x3F

    if as_json:
        typer.echo(json.dumps({
            "tos": tos,
            "dscp": dscp,
            "traffic_class": tc.name,
            "priority": int(tc),
        }, indent=2))
    else:
        console.print(f"  TOS={tos} → DSCP={dscp} → class={tc.name} (priority={int(tc)})")


@app.command("enqueue")
def cmd_enqueue(
    src: str = typer.Option(..., "--src", help="Source IPv8 address."),
    dst: str = typer.Option(..., "--dst", help="Destination IPv8 address."),
    tos: int = typer.Option(0, "--tos", "-t", help="TOS field value."),
    count: int = typer.Option(1, "--count", "-n", help="Number of packets."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Enqueue packets into the shaper."""
    shaper = _get_shaper()
    try:
        src_addr = IPv8Address.parse(src)
        dst_addr = IPv8Address.parse(dst)
    except (ValueError, TypeError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    pkt = IPv8Packet(src=src_addr, dst=dst_addr, tos=tos, payload=b"qos-test")
    accepted = 0
    for _ in range(count):
        if shaper.enqueue(pkt):
            accepted += 1

    if as_json:
        typer.echo(json.dumps({
            "enqueued": accepted,
            "dropped": count - accepted,
            "queue_depth": shaper.queue_depth,
        }, indent=2))
    else:
        console.print(
            f"[green]✓[/green] Enqueued {accepted}/{count} — "
            f"dropped={count - accepted} queue={shaper.queue_depth}"
        )


@app.command("dequeue")
def cmd_dequeue(
    count: int = typer.Option(1, "--count", "-n", help="Number of packets to dequeue."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Dequeue packets from the shaper."""
    shaper = _get_shaper()
    results: list[dict[str, object]] = []
    for _ in range(count):
        pkt = shaper.dequeue()
        if pkt is None:
            break
        tc = classify(pkt)
        results.append({
            "src": str(pkt.src),
            "dst": str(pkt.dst),
            "tos": pkt.tos,
            "class": tc.name,
        })

    if as_json:
        typer.echo(json.dumps({"dequeued": len(results), "packets": results}, indent=2))
    else:
        if not results:
            console.print("[dim]Queue empty.[/dim]")
        else:
            for r in results:
                console.print(f"  {r['src']}→{r['dst']} class={r['class']} tos={r['tos']}")
            console.print(f"[green]✓[/green] Dequeued {len(results)} packet(s)")


@app.command("status")
def cmd_status(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Show shaper status and statistics."""
    shaper = _get_shaper()

    if as_json:
        typer.echo(json.dumps(shaper.to_dict(), indent=2))
        return

    s = shaper.stats()
    console.print(f"[bold]QoS Shaper[/bold] (policy={shaper.policy.name})")
    console.print(f"  Enqueued:  {s.total_enqueued}")
    console.print(f"  Dequeued:  {s.total_dequeued}")
    console.print(f"  Dropped:   {s.total_dropped}")
    console.print(f"  Shaped:    {s.total_shaped}")
    console.print(f"  Queue:     {s.queue_depth}")

    lengths = shaper.get_queue_lengths()
    non_empty = {k: v for k, v in lengths.items() if v > 0}
    if non_empty:
        console.print(f"  Queues:    {non_empty}")


@app.command("queues")
def cmd_queues(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Show per-class queue details."""
    shaper = _get_shaper()
    configs = shaper.all_class_stats()

    if as_json:
        typer.echo(json.dumps([c.to_dict() for c in configs], indent=2))
        return

    table = Table(title="QoS Class Queues", box=None)
    table.add_column("Class", style="cyan")
    table.add_column("Weight", justify="right")
    table.add_column("Rate", justify="right")
    table.add_column("Queue", justify="right")
    table.add_column("In", justify="right")
    table.add_column("Out", justify="right")
    table.add_column("Drop", justify="right")
    for c in configs:
        q_len = len(shaper._queues[c.traffic_class])  # noqa: SLF001
        rate_s = f"{c.rate_bps}bps" if c.rate_bps > 0 else "∞"
        table.add_row(
            c.traffic_class.name, str(c.weight), rate_s,
            str(q_len), str(c.enqueue_count), str(c.dequeue_count), str(c.drop_count),
        )
    console.print(table)


@app.command("demo")
def cmd_demo(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Run a QoS demo showcasing classification and shaping."""
    results: list[dict[str, object]] = []

    # --- Priority Queuing ---
    shaper_pq = TrafficShaper(policy=QoSPolicy.PRIORITY)
    packets_pq = [
        ("64496.10.0.1.10", "64497.10.0.1.1", 0),    # BE (TOS=0)
        ("64496.10.0.1.20", "64497.10.0.1.1", 184),   # EF (DSCP 46 << 2 = 184)
        ("64496.10.0.1.30", "64497.10.0.1.1", 72),    # AF31 (DSCP 26... wait no, 18<<2=72 → AF21)
        ("64496.10.0.1.10", "64497.10.0.1.1", 104),   # AF31 (DSCP 26 << 2 = 104)
    ]
    for src, dst, tos in packets_pq:
        pkt = IPv8Packet(src=IPv8Address.parse(src), dst=IPv8Address.parse(dst), tos=tos, payload=b"pq")
        shaper_pq.enqueue(pkt)

    dequeued_order: list[str] = []
    while True:
        p = shaper_pq.dequeue()
        if p is None:
            break
        dequeued_order.append(classify(p).name)

    results.append({
        "scenario": "priority_queuing",
        "order": dequeued_order,
        "stats": shaper_pq.stats().to_dict(),
    })

    # --- WFQ ---
    shaper_wfq = TrafficShaper(policy=QoSPolicy.WFQ)
    shaper_wfq.configure_class(TrafficClass.EF, weight=3)
    shaper_wfq.configure_class(TrafficClass.BE, weight=1)
    for _ in range(6):
        pkt_ef = IPv8Packet(src=IPv8Address.parse("64496.10.0.1.10"),
                            dst=IPv8Address.parse("64497.10.0.1.1"), tos=184, payload=b"wfq")
        shaper_wfq.enqueue(pkt_ef)
    for _ in range(6):
        pkt_be = IPv8Packet(src=IPv8Address.parse("64496.10.0.1.20"),
                            dst=IPv8Address.parse("64497.10.0.1.1"), tos=0, payload=b"wfq")
        shaper_wfq.enqueue(pkt_be)

    wfq_order: list[str] = []
    while True:
        p = shaper_wfq.dequeue()
        if p is None:
            break
        wfq_order.append(classify(p).name)

    results.append({
        "scenario": "wfq",
        "order": wfq_order,
        "stats": shaper_wfq.stats().to_dict(),
    })

    # --- Rate limiting ---
    shaper_rl = TrafficShaper(policy=QoSPolicy.FIFO)
    shaper_rl.configure_class(TrafficClass.BE, rate_bps=8000, burst_bytes=100, max_queue=100)
    accepted = 0
    for _ in range(20):
        pkt = IPv8Packet(src=IPv8Address.parse("64496.10.0.1.10"),
                         dst=IPv8Address.parse("64497.10.0.1.1"), tos=0, payload=b"x" * 50)
        if shaper_rl.enqueue(pkt):
            accepted += 1
    results.append({
        "scenario": "rate_limiting",
        "attempted": 20,
        "accepted": accepted,
        "dropped": 20 - accepted,
        "stats": shaper_rl.stats().to_dict(),
    })

    if as_json:
        typer.echo(json.dumps({"scenarios": results}, indent=2))
        return

    for r in results:
        console.print(f"\n[bold cyan]━━━ {str(r['scenario']).upper()} ━━━[/bold cyan]")
        for k, v in r.items():
            if k == "scenario":
                continue
            console.print(f"  {k}: {v}")
    console.print("\n[green]✓[/green] QoS demo complete")
