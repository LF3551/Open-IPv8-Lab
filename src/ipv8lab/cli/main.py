# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""ipv8lab CLI — main entry point."""

import typer

from ipv8lab.cli.addr import app as addr_app
from ipv8lab.cli.bench_cli import app as bench_app
from ipv8lab.cli.bgp8_cli import app as bgp8_app
from ipv8lab.cli.capture_cli import app as capture_app
from ipv8lab.cli.cf_dashboard_cli import app as cf_dashboard_app
from ipv8lab.cli.dashboard_cli import app as dashboard_app
from ipv8lab.cli.frag_cli import app as frag_app
from ipv8lab.cli.packet_cli import app as packet_app
from ipv8lab.cli.pcap_cli import app as pcap_app
from ipv8lab.cli.route_cli import app as route_app
from ipv8lab.cli.traceroute_cli import app as traceroute_app
from ipv8lab.cli.udp_cli import app as udp_app
from ipv8lab.cli.multizone_cli import app as multizone_app
from ipv8lab.cli.xlate8_cli import app as xlate8_app
from ipv8lab.cli.zone_cli import app as zone_app

app = typer.Typer(
    name="ipv8lab",
    help="Open-IPv8-Lab — Experimental userspace IPv8 toolkit.",
    no_args_is_help=True,
)

app.add_typer(addr_app, name="addr", help="IPv8 address operations.")
app.add_typer(bench_app, name="bench", help="Performance benchmarks.")
app.add_typer(bgp8_app, name="bgp8", help="BGP8 path selection.")
app.add_typer(packet_app, name="packet", help="IPv8 Lab packet operations.")
app.add_typer(pcap_app, name="pcap", help="PCAP export for Wireshark.")
app.add_typer(route_app, name="route", help="Routing simulation.")
app.add_typer(traceroute_app, name="traceroute", help="Traceroute8 diagnostic utility.")
app.add_typer(udp_app, name="udp", help="UDP transport experiments.")
app.add_typer(capture_app, name="capture", help="Packet capture and replay.")
app.add_typer(cf_dashboard_app, name="cf", help="CF performance dashboard.")
app.add_typer(frag_app, name="frag", help="Packet fragmentation and reassembly.")
app.add_typer(dashboard_app, name="dashboard", help="Web UI dashboard.")
app.add_typer(zone_app, name="zone", help="Zone Server management.")
app.add_typer(multizone_app, name="multizone", help="Multi-zone simulation.")
app.add_typer(xlate8_app, name="xlate8", help="XLATE8 north-south traffic flow.")

if __name__ == "__main__":
    app()
