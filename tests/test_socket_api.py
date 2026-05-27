# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for Socket API Compatibility mock per Section 6.2."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from ipv8lab.address import IPv8Address
from ipv8lab.socket_api import (
    AF_INET,
    AF_INET8,
    CompatLayer,
    SockaddrIn,
    SockaddrIn8,
    SocketType,
    create_socket,
)
from ipv8lab.cli.socket_api_cli import app

runner = CliRunner()


# ===================================================================
# Constants
# ===================================================================

class TestConstants:
    def test_af_inet(self) -> None:
        assert AF_INET == 2

    def test_af_inet8(self) -> None:
        assert AF_INET8 == 46

    def test_socket_types(self) -> None:
        assert SocketType.SOCK_STREAM == 1
        assert SocketType.SOCK_DGRAM == 2


# ===================================================================
# SockaddrIn8
# ===================================================================

class TestSockaddrIn8:
    def test_defaults(self) -> None:
        sa = SockaddrIn8()
        assert sa.sin8_family == AF_INET8
        assert sa.sin8_port == 0
        assert sa.sin8_rn == 0
        assert sa.sin8_addr == "0.0.0.0"

    def test_sin8_asn_alias(self) -> None:
        sa = SockaddrIn8(sin8_rn=64496)
        assert sa.sin8_asn == 64496  # backwards-compat alias

    def test_from_ipv8_address(self) -> None:
        addr = IPv8Address.parse("64496-192.0.2.1")
        sa = SockaddrIn8.from_ipv8_address(addr, port=443)
        assert sa.sin8_family == AF_INET8
        assert sa.sin8_port == 443
        assert sa.sin8_rn == addr.rn
        assert sa.sin8_addr == "192.0.2.1"

    def test_from_ipv4_tuple(self) -> None:
        sa = SockaddrIn8.from_ipv4_tuple(("10.0.0.1", 80), asn=64497)
        assert sa.sin8_port == 80
        assert sa.sin8_rn == 64497
        assert sa.sin8_addr == "10.0.0.1"

    def test_to_ipv8_address(self) -> None:
        sa = SockaddrIn8(sin8_rn=64496, sin8_addr="192.0.2.1", sin8_port=443)
        addr = sa.to_ipv8_address()
        assert addr.rn == 64496
        assert addr.host_str == "192.0.2.1"

    def test_to_dict(self) -> None:
        sa = SockaddrIn8(sin8_rn=64496, sin8_addr="10.0.0.1", sin8_port=80)
        d = sa.to_dict()
        assert d["sin8_family"] == AF_INET8
        assert d["sin8_port"] == 80
        assert d["sin8_rn"] == 64496
        assert d["sin8_addr"] == "10.0.0.1"

    def test_frozen(self) -> None:
        sa = SockaddrIn8()
        try:
            sa.sin8_port = 80  # type: ignore[misc]
            raise AssertionError("should be frozen")
        except AttributeError:
            pass


# ===================================================================
# SockaddrIn (legacy)
# ===================================================================

class TestSockaddrIn:
    def test_defaults(self) -> None:
        sa = SockaddrIn()
        assert sa.sin_family == AF_INET
        assert sa.sin_port == 0
        assert sa.sin_addr == "0.0.0.0"


# ===================================================================
# CompatLayer
# ===================================================================

class TestCompatLayer:
    def test_upgrade_connect_default_asn(self) -> None:
        compat = CompatLayer(default_asn=64496)
        sa8 = compat.upgrade_connect(("10.0.0.1", 80))
        assert sa8.sin8_asn == 64496
        assert sa8.sin8_addr == "10.0.0.1"
        assert sa8.sin8_port == 80

    def test_dns8_resolution(self) -> None:
        compat = CompatLayer()
        compat.register_dns8("example.com", 64497)
        assert compat.resolve("example.com") == 64497
        assert compat.resolve("unknown.com") == 0

    def test_upgrade_with_dns8(self) -> None:
        compat = CompatLayer()
        compat.register_dns8("192.0.2.1", 64496)
        sa8 = compat.upgrade_connect(("192.0.2.1", 443))
        assert sa8.sin8_asn == 64496

    def test_downgrade_to_ipv4(self) -> None:
        compat = CompatLayer()
        sa8 = SockaddrIn8(sin8_rn=64496, sin8_addr="10.0.0.1", sin8_port=80)
        sa4 = compat.downgrade_to_ipv4(sa8)
        assert sa4.sin_family == AF_INET
        assert sa4.sin_addr == "10.0.0.1"
        assert sa4.sin_port == 80


# ===================================================================
# IPv8Socket
# ===================================================================

class TestIPv8Socket:
    def test_create_socket(self) -> None:
        sock = create_socket(family=AF_INET8, default_asn=64496)
        assert sock.family == AF_INET8

    def test_bind(self) -> None:
        sock = create_socket(default_asn=64496)
        sa = SockaddrIn8(sin8_rn=64496, sin8_addr="10.0.0.1", sin8_port=8080)
        sock.bind(sa)
        assert sock.local_address == sa

    def test_connect(self) -> None:
        sock = create_socket(default_asn=64496)
        sa = SockaddrIn8(sin8_rn=64497, sin8_addr="10.0.0.2", sin8_port=443)
        sock.connect(sa)
        assert sock.remote_address == sa

    def test_connect_legacy_tuple(self) -> None:
        sock = create_socket(default_asn=64496)
        sock.connect(("10.0.0.2", 443))
        assert sock.remote_address is not None
        assert sock.remote_address.sin8_asn == 64496
        assert sock.remote_address.sin8_addr == "10.0.0.2"

    def test_send(self) -> None:
        sock = create_socket()
        sock.connect(SockaddrIn8(sin8_addr="10.0.0.1", sin8_port=80))
        n = sock.send(b"hello")
        assert n == 5

    def test_recv(self) -> None:
        sock = create_socket()
        sock.connect(SockaddrIn8(sin8_addr="10.0.0.1", sin8_port=80))
        data = sock.recv()
        assert data == b""

    def test_close(self) -> None:
        sock = create_socket()
        sock.bind(SockaddrIn8(sin8_addr="10.0.0.1"))
        sock.connect(SockaddrIn8(sin8_addr="10.0.0.2", sin8_port=80))
        sock.close()
        assert sock.local_address is None
        assert sock.remote_address is None

    def test_events_recorded(self) -> None:
        sock = create_socket()
        sa = SockaddrIn8(sin8_addr="10.0.0.1", sin8_port=80)
        sock.bind(sa)
        sock.connect(sa)
        sock.send(b"x")
        sock.recv()
        sock.close()
        actions = [e.action for e in sock.events]
        assert actions == ["bind", "connect", "send", "recv", "close"]

    def test_full_cycle(self) -> None:
        sock = create_socket(default_asn=64496)
        sock.compat.register_dns8("10.0.0.2", 64497)
        sock.bind(SockaddrIn8.from_ipv4_tuple(("10.0.0.1", 0), asn=64496))
        sock.connect(("10.0.0.2", 443))
        assert sock.remote_address is not None
        assert sock.remote_address.sin8_asn == 64497
        sock.send(b"GET /")
        sock.close()
        assert len(sock.events) == 4


# ===================================================================
# CLI tests
# ===================================================================

class TestSocketAPICLI:
    def test_info_json(self) -> None:
        result = runner.invoke(app, ["info", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["AF_INET8"] == 46
        assert len(data["sockaddr_in8_fields"]) == 4

    def test_info_text(self) -> None:
        result = runner.invoke(app, ["info"])
        assert result.exit_code == 0
        assert "AF_INET8" in result.output
        assert "sockaddr_in8" in result.output

    def test_create_json(self) -> None:
        result = runner.invoke(app, ["create", "64496-10.0.0.1", "--port", "443", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["sin8_rn"] == 64496
        assert data["sin8_addr"] == "10.0.0.1"
        assert data["sin8_port"] == 443

    def test_create_text(self) -> None:
        result = runner.invoke(app, ["create", "64496-10.0.0.1"])
        assert result.exit_code == 0
        assert "sin8_rn" in result.output

    def test_upgrade_json(self) -> None:
        result = runner.invoke(app, ["upgrade", "10.0.0.1", "--port", "80", "--asn", "64496", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["sin8_rn"] == 64496
        assert data["sin8_addr"] == "10.0.0.1"

    def test_upgrade_text(self) -> None:
        result = runner.invoke(app, ["upgrade", "10.0.0.1"])
        assert result.exit_code == 0
        assert "Upgraded" in result.output

    def test_simulate_json(self) -> None:
        result = runner.invoke(app, [
            "simulate", "64496-10.0.0.1", "64497-10.0.0.2",
            "--port", "443", "--json",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        actions = [e["action"] for e in data]
        assert "bind" in actions
        assert "connect" in actions
        assert "send" in actions
        assert "close" in actions

    def test_simulate_text(self) -> None:
        result = runner.invoke(app, ["simulate", "64496-10.0.0.1", "64497-10.0.0.2"])
        assert result.exit_code == 0
        assert "connect" in result.output

    def test_status_json(self) -> None:
        result = runner.invoke(app, ["status", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["AF_INET8"] == 46

    def test_no_args_help(self) -> None:
        result = runner.invoke(app, [])
        assert result.exit_code in (0, 2)
