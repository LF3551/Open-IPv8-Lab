# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""CLI for standalone NetLog8 protocol per draft-thain-netlog8-00."""

from __future__ import annotations

import json

import typer

from ipv8lab.netlog8 import (
    NetLog8Client,
    NetLog8Facility,
    NetLog8Severity,
)
from ipv8lab.netlog8_proto import (
    AlertRule,
    NetLog8Collector,
    NetLog8Header,
    NetLog8Relay,
    frame_entry,
)

app = typer.Typer(no_args_is_help=True)

_client: NetLog8Client | None = None
_collector: NetLog8Collector | None = None
_relay: NetLog8Relay | None = None


def _get_client() -> NetLog8Client:
    global _client
    if _client is None:
        _client = NetLog8Client(source="cli-device")
    return _client


def _get_collector() -> NetLog8Collector:
    global _collector
    if _collector is None:
        _collector = NetLog8Collector()
    return _collector


@app.command()
def init(
    source: str = typer.Option("cli-device", help="Client source ID"),
    collector_id: str = typer.Option("netlog8-collector", help="Collector ID"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Initialise NetLog8 client and collector."""
    global _client, _collector, _relay
    _client = NetLog8Client(source=source)
    _collector = NetLog8Collector(collector_id=collector_id)
    _relay = NetLog8Relay()
    _relay.add_collector(_collector)
    if as_json:
        typer.echo(json.dumps({"client": source, "collector": collector_id}))
    else:
        typer.echo(f"NetLog8 client '{source}' + collector '{collector_id}' initialised")


@app.command()
def log(
    message: str = typer.Argument(..., help="Log message"),
    severity: str = typer.Option("INFO", help="Severity (EMERGENCY..DEBUG)"),
    facility: str = typer.Option("GENERAL", help="Facility"),
    event_type: str = typer.Option("INFO", help="Event type"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Send a log entry through the protocol stack."""
    c = _get_client()
    col = _get_collector()
    sev = NetLog8Severity[severity.upper()]
    fac = NetLog8Facility[facility.upper()]
    entry = c.log(sev, fac, message, event_type=event_type)
    if entry is not None:
        msg = frame_entry(entry)
        col.ingest(entry)
        if as_json:
            typer.echo(json.dumps(msg.to_dict()))
        else:
            typer.echo(f"[{sev.name}] {message}")
    else:
        if as_json:
            typer.echo(json.dumps({"filtered": True}))
        else:
            typer.echo("Filtered by severity")


@app.command()
def sec_alert(
    message: str = typer.Argument(..., help="Alert message"),
    facility: str = typer.Option("SECURITY", help="Facility"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Generate a SEC-ALERT entry."""
    c = _get_client()
    col = _get_collector()
    fac = NetLog8Facility[facility.upper()]
    entry = c.sec_alert(fac, message)
    if entry is not None:
        col.ingest(entry)
        if as_json:
            typer.echo(json.dumps(entry.to_dict()))
        else:
            typer.echo(f"SEC-ALERT: {message}")


@app.command()
def e3_trap(
    message: str = typer.Argument(..., help="Trap message"),
    facility: str = typer.Option("ROUTING", help="Facility"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Generate an E3 trap entry."""
    c = _get_client()
    col = _get_collector()
    fac = NetLog8Facility[facility.upper()]
    entry = c.e3_trap(fac, message)
    if entry is not None:
        col.ingest(entry)
        if as_json:
            typer.echo(json.dumps(entry.to_dict()))
        else:
            typer.echo(f"E3: {message}")


@app.command(name="query")
def query_entries(
    severity: str = typer.Option("", help="Filter by severity"),
    event_type: str = typer.Option("", help="Filter by event type"),
    source: str = typer.Option("", help="Filter by source"),
    limit: int = typer.Option(20, help="Max results"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Query collected entries."""
    col = _get_collector()
    kwargs: dict[str, object] = {"limit": limit}
    if severity:
        kwargs["severity"] = NetLog8Severity[severity.upper()]
    if event_type:
        kwargs["event_type"] = event_type
    if source:
        kwargs["source"] = source
    results = col.query(**kwargs)  # type: ignore[arg-type]
    if as_json:
        typer.echo(json.dumps([e.to_dict() for e in results]))
    else:
        if not results:
            typer.echo("No entries.")
        else:
            for e in results:
                typer.echo(f"  [{e.severity.name}] {e.event_type}: {e.message}")


@app.command(name="alerts")
def show_alerts(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Show triggered alerts."""
    col = _get_collector()
    data = [a.to_dict() for a in col.alerts]
    if as_json:
        typer.echo(json.dumps(data))
    else:
        if not data:
            typer.echo("No alerts.")
        else:
            for a in col.alerts:
                typer.echo(f"  {a.rule_name}: {a.entry.message}")


@app.command(name="add-rule")
def add_rule(
    name: str = typer.Argument(..., help="Rule name"),
    severity: str = typer.Option("ALERT", help="Minimum severity to trigger"),
    event_types: str = typer.Option("", help="Comma-separated event types"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Add an alert rule to the collector."""
    col = _get_collector()
    evts = tuple(e.strip() for e in event_types.split(",") if e.strip()) if event_types else ()
    rule = AlertRule(
        name=name,
        severity_min=NetLog8Severity[severity.upper()],
        event_types=evts,
    )
    col.add_rule(rule)
    if as_json:
        typer.echo(json.dumps({"name": name, "severity_min": severity, "event_types": list(evts)}))
    else:
        typer.echo(f"Rule '{name}' added")


@app.command()
def export(
    fmt: str = typer.Option("jsonl", help="Export format: jsonl or syslog"),
    limit: int = typer.Option(0, help="Max entries (0 = all)"),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Export collected entries."""
    col = _get_collector()
    if fmt == "syslog":
        lines = col.export_syslog(limit=limit)
        if as_json:
            typer.echo(json.dumps({"format": "syslog", "lines": lines}))
        else:
            for line in lines:
                typer.echo(line)
    else:
        data = col.export_jsonl(limit=limit)
        if as_json:
            typer.echo(json.dumps({"format": "jsonl", "entries": data}))
        else:
            for d in data:
                typer.echo(json.dumps(d))


@app.command()
def header_info(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Show NetLog8 header format info."""
    d = {
        "header_size": NetLog8Header.HEADER_SIZE,
        "struct_fmt": NetLog8Header.STRUCT_FMT,
        "magic": f"0x{0x4E4C3801:08X}",
        "version": 1,
    }
    if as_json:
        typer.echo(json.dumps(d))
    else:
        typer.echo(f"Header: {d['header_size']} bytes, magic={d['magic']}")


@app.command()
def status(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Show protocol status."""
    col = _get_collector()
    d = col.summary()
    if as_json:
        typer.echo(json.dumps(d))
    else:
        typer.echo(f"Collector: {d['collector_id']}")
        typer.echo(f"Received:  {d['received']}")
        typer.echo(f"Buffered:  {d['buffered']}")
        typer.echo(f"Sources:   {d['sources']}")
        typer.echo(f"Rules:     {d['alert_rules']}")
        typer.echo(f"Alerts:    {d['triggered_alerts']}")
