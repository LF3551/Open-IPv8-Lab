# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for TUI dashboard module."""

from __future__ import annotations

from ipv8lab.tui_dashboard import (
    DashboardData,
    DockerNodeInfo,
    FlowInfo,
    NATInfo,
    NodeInfo,
    PanelType,
    QoSInfo,
    RouteInfo,
    TuiDashboard,
    build_demo_data,
    _format_rate,
)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class TestNodeInfo:
    def test_create(self) -> None:
        n = NodeInfo(name="r1", address="64496-10.0.1.1", role="router")
        assert n.name == "r1"
        assert n.role == "router"

    def test_to_row(self) -> None:
        n = NodeInfo(name="h1", address="64496-10.0.1.10", role="host", gateway="r1", route_count=3, link_count=1)
        row = n.to_row()
        assert row == ("h1", "64496-10.0.1.10", "host", "r1", "3", "1")

    def test_default_values(self) -> None:
        n = NodeInfo(name="x", address="64496-10.0.1.1")
        assert n.role == "host"
        assert n.gateway == ""
        assert n.route_count == 0


class TestRouteInfo:
    def test_create(self) -> None:
        r = RouteInfo(destination="64497-0.0.0.0/8", next_hop="r2", metric=10)
        assert r.destination == "64497-0.0.0.0/8"

    def test_to_row(self) -> None:
        r = RouteInfo(destination="10.0.0.0/8", next_hop="gw", interface="eth0", metric=5, tier="local")
        row = r.to_row()
        assert row == ("10.0.0.0/8", "gw", "eth0", "5", "local")

    def test_defaults(self) -> None:
        r = RouteInfo(destination="0.0.0.0/0", next_hop="r1")
        assert r.tier == "global"
        assert r.interface == ""


class TestFlowInfo:
    def test_create(self) -> None:
        f = FlowInfo(src_addr="64496-10.0.1.11", dst_addr="64497-10.0.1.11", protocol=6)
        assert f.protocol == 6

    def test_to_row_tcp(self) -> None:
        f = FlowInfo(src_addr="a", dst_addr="b", protocol=6, src_port=80, dst_port=443, packets=10, octets=1000)
        row = f.to_row()
        assert row[2] == "TCP"

    def test_to_row_udp(self) -> None:
        f = FlowInfo(src_addr="a", dst_addr="b", protocol=17)
        assert f.to_row()[2] == "UDP"

    def test_to_row_icmp(self) -> None:
        f = FlowInfo(src_addr="a", dst_addr="b", protocol=1)
        assert f.to_row()[2] == "ICMP"

    def test_to_row_other(self) -> None:
        f = FlowInfo(src_addr="a", dst_addr="b", protocol=47)
        assert f.to_row()[2] == "47"


class TestQoSInfo:
    def test_create(self) -> None:
        q = QoSInfo(traffic_class="EF", policy="PRIORITY", rate_bps=10_000_000)
        assert q.traffic_class == "EF"

    def test_to_row(self) -> None:
        q = QoSInfo(traffic_class="BE", policy="FIFO", packets_in=100, packets_out=90, packets_dropped=10, queue_depth=5, rate_bps=1_000_000)
        row = q.to_row()
        assert row[0] == "BE"
        assert row[1] == "FIFO"
        assert row[6] == "1.0 Mbps"


class TestNATInfo:
    def test_create(self) -> None:
        m = NATInfo(internal_addr="64496-10.0.1.11", external_addr="64496-10.0.2.100", mode="pat")
        assert m.mode == "pat"

    def test_to_row(self) -> None:
        m = NATInfo(internal_addr="in", external_addr="out", mode="static", internal_port=80, external_port=80, packets_out=50, packets_in=40)
        row = m.to_row()
        assert row == ("in", "80", "out", "80", "static", "50", "40")


class TestDockerNodeInfo:
    def test_create(self) -> None:
        d = DockerNodeInfo(name="r1", address="64496-10.0.1.1", role="router", network_count=3)
        assert d.network_count == 3

    def test_to_row(self) -> None:
        d = DockerNodeInfo(name="r1", address="64496-10.0.1.1", role="router", network_count=2, status="running")
        row = d.to_row()
        assert row == ("r1", "64496-10.0.1.1", "router", "2", "running")


# ---------------------------------------------------------------------------
# PanelType
# ---------------------------------------------------------------------------


class TestPanelType:
    def test_values(self) -> None:
        assert PanelType.TOPOLOGY == "topology"
        assert PanelType.ROUTES == "routes"
        assert PanelType.FLOWS == "flows"
        assert PanelType.QOS == "qos"
        assert PanelType.NAT == "nat"
        assert PanelType.DOCKER == "docker"

    def test_count(self) -> None:
        assert len(PanelType) == 6


# ---------------------------------------------------------------------------
# DashboardData
# ---------------------------------------------------------------------------


class TestDashboardData:
    def test_empty(self) -> None:
        d = DashboardData()
        assert d.title == "IPv8 Lab Dashboard"
        s = d.summary()
        assert all(v == 0 for v in s.values())

    def test_summary(self) -> None:
        d = DashboardData(
            nodes=[NodeInfo(name="r1", address="a")],
            routes=[RouteInfo(destination="b", next_hop="c")],
            flows=[FlowInfo(src_addr="d", dst_addr="e")],
        )
        s = d.summary()
        assert s["nodes"] == 1
        assert s["routes"] == 1
        assert s["flows"] == 1

    def test_to_dict(self) -> None:
        d = DashboardData(title="test", nodes=[NodeInfo(name="r1", address="a")])
        out = d.to_dict()
        assert out["title"] == "test"
        assert len(out["nodes"]) == 1  # type: ignore[arg-type]
        assert "summary" in out

    def test_custom_title(self) -> None:
        d = DashboardData(title="My Lab")
        assert d.title == "My Lab"


# ---------------------------------------------------------------------------
# build_demo_data
# ---------------------------------------------------------------------------


class TestBuildDemoData:
    def test_returns_data(self) -> None:
        data = build_demo_data()
        assert isinstance(data, DashboardData)

    def test_has_nodes(self) -> None:
        data = build_demo_data()
        assert len(data.nodes) >= 4

    def test_has_routes(self) -> None:
        data = build_demo_data()
        assert len(data.routes) >= 3

    def test_has_flows(self) -> None:
        data = build_demo_data()
        assert len(data.flows) >= 2

    def test_has_qos(self) -> None:
        data = build_demo_data()
        assert len(data.qos_classes) >= 2

    def test_has_nat(self) -> None:
        data = build_demo_data()
        assert len(data.nat_mappings) >= 2

    def test_has_docker(self) -> None:
        data = build_demo_data()
        assert len(data.docker_nodes) >= 2

    def test_summary_nonzero(self) -> None:
        data = build_demo_data()
        s = data.summary()
        assert all(v > 0 for v in s.values())


# ---------------------------------------------------------------------------
# _format_rate
# ---------------------------------------------------------------------------


class TestFormatRate:
    def test_bps(self) -> None:
        assert _format_rate(500) == "500 bps"

    def test_kbps(self) -> None:
        assert _format_rate(1500) == "1.5 Kbps"

    def test_mbps(self) -> None:
        assert _format_rate(10_000_000) == "10.0 Mbps"

    def test_gbps(self) -> None:
        assert _format_rate(2_500_000_000) == "2.5 Gbps"

    def test_zero(self) -> None:
        assert _format_rate(0) == "0 bps"


# ---------------------------------------------------------------------------
# TuiDashboard (unit tests, no interactive run)
# ---------------------------------------------------------------------------


class TestTuiDashboard:
    def test_create_default(self) -> None:
        dashboard = TuiDashboard()
        assert dashboard.data.title == "IPv8 Lab Dashboard"

    def test_create_with_data(self) -> None:
        data = build_demo_data()
        dashboard = TuiDashboard(data=data)
        assert dashboard.data.title == data.title
        assert len(dashboard.data.nodes) == len(data.nodes)

    def test_update_data(self) -> None:
        dashboard = TuiDashboard()
        new_data = DashboardData(title="Updated")
        # update_data requires mounted app, test the data attribute
        dashboard._data = new_data
        assert dashboard.data.title == "Updated"

    def test_bindings(self) -> None:
        dashboard = TuiDashboard()
        binding_keys = [b.key for b in dashboard.BINDINGS]
        assert "q" in binding_keys
        assert "r" in binding_keys
        assert "d" in binding_keys
