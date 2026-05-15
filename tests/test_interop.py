# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for Inter-Company Interop and Two-XLATE8 model (Sections 4.6–4.7)."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from ipv8lab.interop import (
    INTEROP_PREFIX,
    InteropEntry,
    InteropXLATE8Engine,
    TwoXLATE8Bridge,
    is_interop_prefix,
    make_interop_bridge,
    validate_interop_isolation,
)
from ipv8lab.cli.interop_cli import app


runner = CliRunner()


# ===================================================================
# InteropXLATE8Engine
# ===================================================================

class TestInteropXLATE8Engine:
    def test_expose_service(self) -> None:
        engine = InteropXLATE8Engine("Acme", "127.1.0.0")
        entry = engine.expose_service("127.1.0.0.10.0.0.5", "10.0.0.5")
        assert entry.internal_address == "127.1.0.0.10.0.0.5"
        assert entry.interop_address == "127.127.0.0.10.0.0.5"
        assert engine.size == 1

    def test_expose_custom_port(self) -> None:
        engine = InteropXLATE8Engine("Acme", "127.1.0.0")
        entry = engine.expose_service("127.1.0.0.10.0.0.5", "10.0.0.5", internal_port=8080, interop_port=8080)
        assert entry.internal_port == 8080

    def test_translate_outbound(self) -> None:
        engine = InteropXLATE8Engine("Acme", "127.1.0.0")
        engine.expose_service("127.1.0.0.10.0.0.5", "10.0.0.5")
        assert engine.translate_outbound("127.1.0.0.10.0.0.5") == "127.127.0.0.10.0.0.5"

    def test_translate_outbound_missing(self) -> None:
        engine = InteropXLATE8Engine("Acme", "127.1.0.0")
        assert engine.translate_outbound("127.1.0.0.99.99.99.99") is None

    def test_translate_inbound(self) -> None:
        engine = InteropXLATE8Engine("Acme", "127.1.0.0")
        engine.expose_service("127.1.0.0.10.0.0.5", "10.0.0.5")
        assert engine.translate_inbound("127.127.0.0.10.0.0.5") == "127.1.0.0.10.0.0.5"

    def test_translate_inbound_missing(self) -> None:
        engine = InteropXLATE8Engine("Acme", "127.1.0.0")
        assert engine.translate_inbound("127.127.0.0.99.99.99.99") is None

    def test_entries(self) -> None:
        engine = InteropXLATE8Engine("Acme", "127.1.0.0")
        engine.expose_service("127.1.0.0.10.0.0.5", "10.0.0.5")
        engine.expose_service("127.1.0.0.10.0.0.6", "10.0.0.6")
        assert len(engine.entries()) == 2

    def test_multiple_services(self) -> None:
        engine = InteropXLATE8Engine("Acme", "127.1.0.0")
        engine.expose_service("127.1.0.0.10.0.0.1", "10.0.0.1")
        engine.expose_service("127.1.0.0.10.0.0.2", "10.0.0.2")
        assert engine.translate_outbound("127.1.0.0.10.0.0.1") == "127.127.0.0.10.0.0.1"
        assert engine.translate_outbound("127.1.0.0.10.0.0.2") == "127.127.0.0.10.0.0.2"


# ===================================================================
# TwoXLATE8Bridge (Section 4.7)
# ===================================================================

class TestTwoXLATE8Bridge:
    def _make_bridge(self) -> TwoXLATE8Bridge:
        bridge = make_interop_bridge("Acme", "127.1.0.0", "Globex", "127.2.0.0")
        bridge.engine_a.expose_service("127.1.0.0.10.0.0.5", "10.0.0.5")
        bridge.engine_b.expose_service("127.2.0.0.10.0.0.10", "10.0.0.10")
        return bridge

    def test_send_a_to_b_delivered(self) -> None:
        bridge = self._make_bridge()
        flow = bridge.send("A", "127.1.0.0.10.0.0.5", "10.0.0.10")
        steps = [e.step for e in flow]
        assert "xlate8_outbound" in steps
        assert "interop_dmz" in steps
        assert "xlate8_inbound" in steps
        assert "delivered" in steps

    def test_send_b_to_a_delivered(self) -> None:
        bridge = self._make_bridge()
        flow = bridge.send("B", "127.2.0.0.10.0.0.10", "10.0.0.5")
        steps = [e.step for e in flow]
        assert "delivered" in steps

    def test_a_never_sees_b_internals(self) -> None:
        """Company A never sees Company B's 127.2.0.0 addresses."""
        bridge = self._make_bridge()
        flow = bridge.send("A", "127.1.0.0.10.0.0.5", "10.0.0.10")
        # In the flow from A's perspective, 127.2.0.0 only appears at inbound
        # step on B's side — A never transmits to 127.2.0.0 directly
        outbound_event = [e for e in flow if e.step == "xlate8_outbound"][0]
        assert "127.2.0.0" not in outbound_event.src
        assert "127.2.0.0" not in outbound_event.dst

    def test_blocked_no_src_mapping(self) -> None:
        bridge = make_interop_bridge()
        flow = bridge.send("A", "127.1.0.0.99.99.99.99", "10.0.0.10")
        assert flow[-1].step == "blocked"

    def test_blocked_no_dst_mapping(self) -> None:
        bridge = make_interop_bridge()
        bridge.engine_a.expose_service("127.1.0.0.10.0.0.5", "10.0.0.5")
        flow = bridge.send("A", "127.1.0.0.10.0.0.5", "99.99.99.99")
        assert flow[-1].step == "blocked"

    def test_events_accumulated(self) -> None:
        bridge = self._make_bridge()
        bridge.send("A", "127.1.0.0.10.0.0.5", "10.0.0.10")
        bridge.send("B", "127.2.0.0.10.0.0.10", "10.0.0.5")
        assert len(bridge.events) == 8  # 4 per successful flow

    def test_clear_events(self) -> None:
        bridge = self._make_bridge()
        bridge.send("A", "127.1.0.0.10.0.0.5", "10.0.0.10")
        cleared = bridge.clear_events()
        assert cleared == 4
        assert len(bridge.events) == 0

    def test_no_address_overlap(self) -> None:
        """No address overlap possible between companies."""
        bridge = self._make_bridge()
        a_internals = {e.internal_address for e in bridge.engine_a.entries()}
        b_internals = {e.internal_address for e in bridge.engine_b.entries()}
        assert a_internals.isdisjoint(b_internals)


# ===================================================================
# Validation
# ===================================================================

class TestValidation:
    def test_isolation_ok(self) -> None:
        bridge = make_interop_bridge()
        bridge.engine_a.expose_service("127.1.0.0.10.0.0.5", "10.0.0.5")
        bridge.engine_b.expose_service("127.2.0.0.10.0.0.10", "10.0.0.10")
        assert validate_interop_isolation(bridge) == []

    def test_is_interop_true(self) -> None:
        assert is_interop_prefix("127.127.0.0.10.0.0.5") is True

    def test_is_interop_false(self) -> None:
        assert is_interop_prefix("127.1.0.0.10.0.0.5") is False
        assert is_interop_prefix("10.0.0.1") is False

    def test_interop_prefix_constant(self) -> None:
        assert INTEROP_PREFIX == "127.127.0.0"


# ===================================================================
# InteropEntry dataclass
# ===================================================================

class TestInteropEntry:
    def test_frozen(self) -> None:
        e = InteropEntry("127.1.0.0.10.0.0.1", "127.127.0.0.10.0.0.1")
        with pytest.raises(AttributeError):
            e.internal_address = "x"  # type: ignore[misc]

    def test_defaults(self) -> None:
        e = InteropEntry("a", "b")
        assert e.protocol == 6
        assert e.internal_port == 0


# ===================================================================
# make_interop_bridge factory
# ===================================================================

class TestFactory:
    def test_defaults(self) -> None:
        bridge = make_interop_bridge()
        assert bridge.engine_a.company_name == "Company-A"
        assert bridge.engine_b.company_name == "Company-B"
        assert bridge.engine_a.internal_prefix == "127.1.0.0"
        assert bridge.engine_b.internal_prefix == "127.2.0.0"

    def test_custom(self) -> None:
        bridge = make_interop_bridge("X", "127.10.0.0", "Y", "127.20.0.0")
        assert bridge.engine_a.company_name == "X"
        assert bridge.engine_b.internal_prefix == "127.20.0.0"


# ===================================================================
# CLI tests
# ===================================================================

class TestInteropCLI:
    def test_init_json(self) -> None:
        result = runner.invoke(app, ["init", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["interop_prefix"] == "127.127.0.0"

    def test_init_text(self) -> None:
        result = runner.invoke(app, ["init"])
        assert result.exit_code == 0
        assert "Bridge initialised" in result.output

    def test_expose_json(self) -> None:
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["expose", "A", "127.1.0.0.10.0.0.5", "10.0.0.5", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["interop"] == "127.127.0.0.10.0.0.5"

    def test_expose_text(self) -> None:
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["expose", "B", "127.2.0.0.10.0.0.10", "10.0.0.10"])
        assert result.exit_code == 0
        assert "127.127.0.0.10.0.0.10" in result.output

    def test_send_json(self) -> None:
        runner.invoke(app, ["init"])
        runner.invoke(app, ["expose", "A", "127.1.0.0.10.0.0.5", "10.0.0.5"])
        runner.invoke(app, ["expose", "B", "127.2.0.0.10.0.0.10", "10.0.0.10"])
        result = runner.invoke(app, ["send", "A", "127.1.0.0.10.0.0.5", "10.0.0.10", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        steps = [e["step"] for e in data]
        assert "delivered" in steps

    def test_send_text(self) -> None:
        runner.invoke(app, ["init"])
        runner.invoke(app, ["expose", "A", "127.1.0.0.10.0.0.5", "10.0.0.5"])
        runner.invoke(app, ["expose", "B", "127.2.0.0.10.0.0.10", "10.0.0.10"])
        result = runner.invoke(app, ["send", "A", "127.1.0.0.10.0.0.5", "10.0.0.10"])
        assert result.exit_code == 0
        assert "delivered" in result.output

    def test_table_json(self) -> None:
        runner.invoke(app, ["init"])
        runner.invoke(app, ["expose", "A", "127.1.0.0.10.0.0.5", "10.0.0.5"])
        result = runner.invoke(app, ["table", "A", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 1

    def test_table_empty(self) -> None:
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["table", "B"])
        assert result.exit_code == 0
        assert "no interop" in result.output.lower()

    def test_validate_json(self) -> None:
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["validate", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["ok"] is True

    def test_validate_text(self) -> None:
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["validate"])
        assert result.exit_code == 0
        assert "OK" in result.output

    def test_events_empty(self) -> None:
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["events"])
        assert result.exit_code == 0
        assert "no events" in result.output.lower()

    def test_events_json(self) -> None:
        runner.invoke(app, ["init"])
        runner.invoke(app, ["expose", "A", "127.1.0.0.10.0.0.5", "10.0.0.5"])
        runner.invoke(app, ["expose", "B", "127.2.0.0.10.0.0.10", "10.0.0.10"])
        runner.invoke(app, ["send", "A", "127.1.0.0.10.0.0.5", "10.0.0.10"])
        result = runner.invoke(app, ["events", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) >= 4

    def test_check_interop(self) -> None:
        result = runner.invoke(app, ["check", "127.127.0.0.10.0.0.5", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["is_interop"] is True

    def test_check_not_interop(self) -> None:
        result = runner.invoke(app, ["check", "127.1.0.0.10.0.0.5", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["is_interop"] is False

    def test_status_json(self) -> None:
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["status", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "company_a" in data
        assert "company_b" in data

    def test_status_text(self) -> None:
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["status"])
        assert result.exit_code == 0
        assert "Company" in result.output

    def test_demo_json(self) -> None:
        result = runner.invoke(app, ["demo", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "a_to_b" in data
        assert "b_to_a" in data
        assert data["isolation_ok"] is True

    def test_demo_text(self) -> None:
        result = runner.invoke(app, ["demo"])
        assert result.exit_code == 0
        assert "Acme-Corp" in result.output
        assert "Globex-Inc" in result.output
        assert "Isolation: OK" in result.output

    def test_no_args_help(self) -> None:
        result = runner.invoke(app, [])
        assert result.exit_code in (0, 2)
