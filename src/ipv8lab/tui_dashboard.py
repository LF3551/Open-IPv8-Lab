# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""TUI dashboard for IPv8 Lab using Textual / Rich.

Provides a terminal UI with live-updating panels for:
- Network topology overview (nodes, links, roles)
- Route table viewer (tier1/tier2)
- NetFlow8 active flows
- QoS class statistics
- NAT8 mapping table
- Docker testbed status

The dashboard can run in two modes:
1. Live mode — refreshes data periodically from a running simulation
2. Snapshot mode — displays a static snapshot of current state

Usage::

    from ipv8lab.tui_dashboard import TuiDashboard, DashboardData
    data = DashboardData(nodes=[...], routes=[...], flows=[...])
    app = TuiDashboard(data=data)
    app.run()
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.reactive import reactive
from textual.widgets import DataTable, Footer, Header, Static, TabbedContent, TabPane


# ---------------------------------------------------------------------------
# Data models for the dashboard
# ---------------------------------------------------------------------------


class PanelType(str, Enum):
    """Available dashboard panels."""

    TOPOLOGY = "topology"
    ROUTES = "routes"
    FLOWS = "flows"
    QOS = "qos"
    NAT = "nat"
    DOCKER = "docker"


@dataclass(slots=True)
class NodeInfo:
    """Node information for display."""

    name: str
    address: str
    role: str = "host"
    gateway: str = ""
    route_count: int = 0
    link_count: int = 0

    def to_row(self) -> tuple[str, ...]:
        return (self.name, self.address, self.role, self.gateway or "-", str(self.route_count), str(self.link_count))


@dataclass(slots=True)
class RouteInfo:
    """Route entry for display."""

    destination: str
    next_hop: str
    interface: str = ""
    metric: int = 0
    tier: str = "global"

    def to_row(self) -> tuple[str, ...]:
        return (self.destination, self.next_hop, self.interface or "-", str(self.metric), self.tier)


@dataclass(slots=True)
class FlowInfo:
    """Flow record for display."""

    src_addr: str
    dst_addr: str
    protocol: int = 6
    src_port: int = 0
    dst_port: int = 0
    packets: int = 0
    octets: int = 0

    def to_row(self) -> tuple[str, ...]:
        proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(self.protocol, str(self.protocol))
        return (self.src_addr, self.dst_addr, proto_name, str(self.src_port), str(self.dst_port), str(self.packets), str(self.octets))


@dataclass(slots=True)
class QoSInfo:
    """QoS class statistics for display."""

    traffic_class: str
    policy: str = "FIFO"
    packets_in: int = 0
    packets_out: int = 0
    packets_dropped: int = 0
    queue_depth: int = 0
    rate_bps: int = 0

    def to_row(self) -> tuple[str, ...]:
        return (self.traffic_class, self.policy, str(self.packets_in), str(self.packets_out), str(self.packets_dropped), str(self.queue_depth), _format_rate(self.rate_bps))


@dataclass(slots=True)
class NATInfo:
    """NAT mapping for display."""

    internal_addr: str
    external_addr: str
    mode: str = "dynamic"
    internal_port: int = 0
    external_port: int = 0
    packets_out: int = 0
    packets_in: int = 0

    def to_row(self) -> tuple[str, ...]:
        return (self.internal_addr, str(self.internal_port), self.external_addr, str(self.external_port), self.mode, str(self.packets_out), str(self.packets_in))


@dataclass(slots=True)
class DockerNodeInfo:
    """Docker testbed node info."""

    name: str
    address: str
    role: str = "host"
    network_count: int = 0
    status: str = "configured"

    def to_row(self) -> tuple[str, ...]:
        return (self.name, self.address, self.role, str(self.network_count), self.status)


@dataclass(slots=True)
class DashboardData:
    """Complete data for the TUI dashboard."""

    title: str = "IPv8 Lab Dashboard"
    nodes: list[NodeInfo] = field(default_factory=list)
    routes: list[RouteInfo] = field(default_factory=list)
    flows: list[FlowInfo] = field(default_factory=list)
    qos_classes: list[QoSInfo] = field(default_factory=list)
    nat_mappings: list[NATInfo] = field(default_factory=list)
    docker_nodes: list[DockerNodeInfo] = field(default_factory=list)

    def summary(self) -> dict[str, int]:
        return {
            "nodes": len(self.nodes),
            "routes": len(self.routes),
            "flows": len(self.flows),
            "qos_classes": len(self.qos_classes),
            "nat_mappings": len(self.nat_mappings),
            "docker_nodes": len(self.docker_nodes),
        }

    def to_dict(self) -> dict[str, object]:
        return {
            "title": self.title,
            "summary": self.summary(),
            "nodes": [asdict(n) for n in self.nodes],
            "routes": [asdict(r) for r in self.routes],
            "flows": [asdict(f) for f in self.flows],
            "qos_classes": [asdict(q) for q in self.qos_classes],
            "nat_mappings": [asdict(m) for m in self.nat_mappings],
            "docker_nodes": [asdict(d) for d in self.docker_nodes],
        }


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _format_rate(bps: int) -> str:
    """Format bits per second for display."""
    if bps >= 1_000_000_000:
        return f"{bps / 1_000_000_000:.1f} Gbps"
    if bps >= 1_000_000:
        return f"{bps / 1_000_000:.1f} Mbps"
    if bps >= 1_000:
        return f"{bps / 1_000:.1f} Kbps"
    return f"{bps} bps"


def build_demo_data() -> DashboardData:
    """Build demonstration data for the TUI dashboard."""
    nodes = [
        NodeInfo(name="r1-as64496", address="64496-10.0.1.1", role="router", route_count=5, link_count=3),
        NodeInfo(name="r2-as64497", address="64497-10.0.1.1", role="router", route_count=4, link_count=2),
        NodeInfo(name="h1-as64496", address="64496-10.0.1.11", role="host", gateway="r1-as64496", link_count=1),
        NodeInfo(name="h2-as64496", address="64496-10.0.1.12", role="host", gateway="r1-as64496", link_count=1),
        NodeInfo(name="h1-as64497", address="64497-10.0.1.11", role="host", gateway="r2-as64497", link_count=1),
        NodeInfo(name="nat-gw", address="64496-10.0.2.1", role="nat_gateway", route_count=3, link_count=2),
    ]

    routes = [
        RouteInfo(destination="64497-0.0.0.0/8", next_hop="r2-as64497", interface="eth0", metric=10, tier="global"),
        RouteInfo(destination="64496-10.0.1.0/24", next_hop="direct", interface="eth1", metric=0, tier="local"),
        RouteInfo(destination="64496-10.0.2.0/24", next_hop="nat-gw", interface="eth2", metric=5, tier="local"),
        RouteInfo(destination="0.0.0.0.0/0", next_hop="r1-as64496", interface="eth0", metric=100, tier="global"),
        RouteInfo(destination="64497-10.0.1.0/24", next_hop="r2-as64497", interface="eth0", metric=15, tier="global"),
    ]

    flows = [
        FlowInfo(src_addr="64496-10.0.1.11", dst_addr="64497-10.0.1.11", protocol=6, src_port=45200, dst_port=80, packets=152, octets=98304),
        FlowInfo(src_addr="64496-10.0.1.12", dst_addr="64497-10.0.1.11", protocol=17, src_port=53000, dst_port=53, packets=24, octets=2048),
        FlowInfo(src_addr="64497-10.0.1.11", dst_addr="64496-10.0.1.11", protocol=6, src_port=80, dst_port=45200, packets=148, octets=524288),
        FlowInfo(src_addr="64496-10.0.1.11", dst_addr="64496-10.0.2.1", protocol=1, src_port=0, dst_port=0, packets=5, octets=320),
    ]

    qos_classes = [
        QoSInfo(traffic_class="EF", policy="PRIORITY", packets_in=500, packets_out=500, packets_dropped=0, queue_depth=2, rate_bps=10_000_000),
        QoSInfo(traffic_class="AF41", policy="WFQ", packets_in=1200, packets_out=1180, packets_dropped=20, queue_depth=15, rate_bps=50_000_000),
        QoSInfo(traffic_class="AF31", policy="WFQ", packets_in=800, packets_out=790, packets_dropped=10, queue_depth=8, rate_bps=30_000_000),
        QoSInfo(traffic_class="BE", policy="FIFO", packets_in=5000, packets_out=4800, packets_dropped=200, queue_depth=50, rate_bps=100_000_000),
    ]

    nat_mappings = [
        NATInfo(internal_addr="64496-10.0.1.11", external_addr="64496-10.0.2.100", mode="dynamic", internal_port=45200, external_port=45200, packets_out=152, packets_in=148),
        NATInfo(internal_addr="64496-10.0.1.12", external_addr="64496-10.0.2.100", mode="pat", internal_port=53000, external_port=60001, packets_out=24, packets_in=24),
        NATInfo(internal_addr="64496-10.0.1.99", external_addr="64496-10.0.2.50", mode="static", internal_port=0, external_port=0, packets_out=1000, packets_in=950),
    ]

    docker_nodes = [
        DockerNodeInfo(name="r1-as64496", address="64496-10.0.1.1", role="router", network_count=3, status="running"),
        DockerNodeInfo(name="r2-as64497", address="64497-10.0.1.1", role="router", network_count=2, status="running"),
        DockerNodeInfo(name="h1-as64496", address="64496-10.0.1.11", role="host", network_count=1, status="running"),
        DockerNodeInfo(name="nat-gw", address="64496-10.0.2.1", role="nat_gateway", network_count=2, status="running"),
    ]

    return DashboardData(
        title="IPv8 Lab — Demo Network",
        nodes=nodes,
        routes=routes,
        flows=flows,
        qos_classes=qos_classes,
        nat_mappings=nat_mappings,
        docker_nodes=docker_nodes,
    )


# ---------------------------------------------------------------------------
# Status bar widget
# ---------------------------------------------------------------------------


class StatusBar(Static):
    """Status bar showing summary counts."""

    def __init__(self, data: DashboardData) -> None:
        super().__init__()
        self._data = data

    def compose(self) -> ComposeResult:
        s = self._data.summary()
        text = (
            f" Nodes: {s['nodes']} │ Routes: {s['routes']} │ "
            f"Flows: {s['flows']} │ QoS: {s['qos_classes']} │ "
            f"NAT: {s['nat_mappings']} │ Docker: {s['docker_nodes']}"
        )
        yield Static(text, id="status-text")


# ---------------------------------------------------------------------------
# TUI Dashboard Application
# ---------------------------------------------------------------------------


class TuiDashboard(App[None]):
    """IPv8 Lab TUI Dashboard with tabbed panels.

    Displays network topology, route tables, flow data,
    QoS statistics, NAT mappings, and Docker testbed status.
    """

    CSS = """
    Screen {
        background: $surface;
    }
    #status-bar {
        dock: bottom;
        height: 1;
        background: $primary;
        color: $text;
        padding: 0 1;
    }
    #status-text {
        width: 100%;
    }
    DataTable {
        height: 1fr;
    }
    TabbedContent {
        height: 1fr;
    }
    TabPane {
        padding: 0;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "refresh", "Refresh"),
        Binding("d", "toggle_dark", "Dark/Light"),
    ]

    TITLE = "IPv8 Lab TUI Dashboard"

    refresh_count: reactive[int] = reactive(0)

    def __init__(self, data: DashboardData | None = None) -> None:
        super().__init__()
        self._data = data or DashboardData()
        self.title = self._data.title

    @property
    def data(self) -> DashboardData:
        return self._data

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent():
            with TabPane("Topology", id="tab-topology"):
                yield DataTable(id="tbl-topology")
            with TabPane("Routes", id="tab-routes"):
                yield DataTable(id="tbl-routes")
            with TabPane("Flows", id="tab-flows"):
                yield DataTable(id="tbl-flows")
            with TabPane("QoS", id="tab-qos"):
                yield DataTable(id="tbl-qos")
            with TabPane("NAT", id="tab-nat"):
                yield DataTable(id="tbl-nat")
            with TabPane("Docker", id="tab-docker"):
                yield DataTable(id="tbl-docker")
        yield Static(id="status-bar")
        yield Footer()

    def on_mount(self) -> None:
        self._populate_tables()
        self._update_status()

    def _populate_tables(self) -> None:
        """Fill all data tables with current data."""
        # Topology
        tbl = self.query_one("#tbl-topology", DataTable)
        tbl.clear(columns=True)
        tbl.add_columns("Name", "Address", "Role", "Gateway", "Routes", "Links")
        for n in self._data.nodes:
            tbl.add_row(*n.to_row())

        # Routes
        tbl = self.query_one("#tbl-routes", DataTable)
        tbl.clear(columns=True)
        tbl.add_columns("Destination", "Next Hop", "Interface", "Metric", "Tier")
        for r in self._data.routes:
            tbl.add_row(*r.to_row())

        # Flows
        tbl = self.query_one("#tbl-flows", DataTable)
        tbl.clear(columns=True)
        tbl.add_columns("Source", "Destination", "Proto", "SrcPort", "DstPort", "Packets", "Octets")
        for f in self._data.flows:
            tbl.add_row(*f.to_row())

        # QoS
        tbl = self.query_one("#tbl-qos", DataTable)
        tbl.clear(columns=True)
        tbl.add_columns("Class", "Policy", "PktsIn", "PktsOut", "Dropped", "Queue", "Rate")
        for q in self._data.qos_classes:
            tbl.add_row(*q.to_row())

        # NAT
        tbl = self.query_one("#tbl-nat", DataTable)
        tbl.clear(columns=True)
        tbl.add_columns("Internal", "IntPort", "External", "ExtPort", "Mode", "PktsOut", "PktsIn")
        for m in self._data.nat_mappings:
            tbl.add_row(*m.to_row())

        # Docker
        tbl = self.query_one("#tbl-docker", DataTable)
        tbl.clear(columns=True)
        tbl.add_columns("Container", "Address", "Role", "Networks", "Status")
        for d in self._data.docker_nodes:
            tbl.add_row(*d.to_row())

    def _update_status(self) -> None:
        """Update status bar."""
        s = self._data.summary()
        text = (
            f" Nodes: {s['nodes']} │ Routes: {s['routes']} │ "
            f"Flows: {s['flows']} │ QoS: {s['qos_classes']} │ "
            f"NAT: {s['nat_mappings']} │ Docker: {s['docker_nodes']}"
        )
        bar = self.query_one("#status-bar", Static)
        bar.update(text)

    def update_data(self, data: DashboardData) -> None:
        """Update the dashboard with new data."""
        self._data = data
        self.title = data.title
        self._populate_tables()
        self._update_status()

    def action_refresh(self) -> None:
        """Refresh data tables."""
        self.refresh_count += 1
        self._populate_tables()
        self._update_status()
        self.notify("Dashboard refreshed")

    def action_toggle_dark(self) -> None:
        """Toggle dark mode."""
        self.theme = "textual-light" if self.theme == "textual-dark" else "textual-dark"
