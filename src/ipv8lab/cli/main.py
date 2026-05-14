# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""ipv8lab CLI — main entry point."""

import typer

from ipv8lab.cli.addr import app as addr_app
from ipv8lab.cli.bench_cli import app as bench_app
from ipv8lab.cli.capture_cli import app as capture_app
from ipv8lab.cli.dashboard_cli import app as dashboard_app
from ipv8lab.cli.packet_cli import app as packet_app
from ipv8lab.cli.route_cli import app as route_app
from ipv8lab.cli.udp_cli import app as udp_app
from ipv8lab.cli.zone_cli import app as zone_app

app = typer.Typer(
    name="ipv8lab",
    help="Open-IPv8-Lab — Experimental userspace IPv8 toolkit.",
    no_args_is_help=True,
)

app.add_typer(addr_app, name="addr", help="IPv8 address operations.")
app.add_typer(bench_app, name="bench", help="Performance benchmarks.")
app.add_typer(packet_app, name="packet", help="IPv8 Lab packet operations.")
app.add_typer(route_app, name="route", help="Routing simulation.")
app.add_typer(udp_app, name="udp", help="UDP transport experiments.")
app.add_typer(capture_app, name="capture", help="Packet capture and replay.")
app.add_typer(dashboard_app, name="dashboard", help="Web UI dashboard.")
app.add_typer(zone_app, name="zone", help="Zone Server management.")

if __name__ == "__main__":
    app()
