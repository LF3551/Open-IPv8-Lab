# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for the plugin system."""

from __future__ import annotations

from typing import Any

from ipv8lab.address import IPv8Address
from ipv8lab.packet import IPv8Packet
from ipv8lab.plugin import PluginInfo, PluginRegistry


def _make_packet() -> IPv8Packet:
    return IPv8Packet(
        src=IPv8Address.parse("1.0.0.0.10.0.0.1"),
        dst=IPv8Address.parse("2.0.0.0.10.0.0.2"),
        payload=b"test",
    )


class TestPluginRegistry:
    def test_register_plugin(self) -> None:
        reg = PluginRegistry()
        info = PluginInfo(name="test-plugin", version="1.0.0")
        reg.register_plugin(info)
        assert len(reg.plugins) == 1
        assert reg.plugins[0].name == "test-plugin"

    def test_packet_hook_passthrough(self) -> None:
        reg = PluginRegistry()
        reg.add_packet_hook(lambda pkt, node: pkt)
        pkt = _make_packet()
        result = reg.apply_packet_hooks(pkt, "node-a")
        assert result is pkt

    def test_packet_hook_drop(self) -> None:
        reg = PluginRegistry()
        reg.add_packet_hook(lambda pkt, node: None)
        pkt = _make_packet()
        result = reg.apply_packet_hooks(pkt, "node-a")
        assert result is None

    def test_packet_hook_chain(self) -> None:
        reg = PluginRegistry()
        calls: list[str] = []

        def hook1(pkt: IPv8Packet, node: str) -> IPv8Packet:
            calls.append("hook1")
            return pkt

        def hook2(pkt: IPv8Packet, node: str) -> IPv8Packet:
            calls.append("hook2")
            return pkt

        reg.add_packet_hook(hook1)
        reg.add_packet_hook(hook2)
        reg.apply_packet_hooks(_make_packet(), "node-a")
        assert calls == ["hook1", "hook2"]

    def test_packet_hook_drop_stops_chain(self) -> None:
        reg = PluginRegistry()
        calls: list[str] = []

        reg.add_packet_hook(lambda pkt, node: None)
        reg.add_packet_hook(lambda pkt, node: (calls.append("should-not-run"), pkt)[-1])
        reg.apply_packet_hooks(_make_packet(), "node-a")
        assert calls == []

    def test_event_hook(self) -> None:
        reg = PluginRegistry()
        events: list[tuple[str, dict[str, Any]]] = []
        reg.add_event_hook(lambda evt, data: events.append((evt, data)))
        reg.emit_event("node_added", {"name": "node-a"})
        assert len(events) == 1
        assert events[0] == ("node_added", {"name": "node-a"})

    def test_emit_event_no_data(self) -> None:
        reg = PluginRegistry()
        events: list[tuple[str, dict[str, Any]]] = []
        reg.add_event_hook(lambda evt, data: events.append((evt, data)))
        reg.emit_event("test")
        assert events[0] == ("test", {})

    def test_load_plugin_missing_register(self) -> None:
        import pytest

        reg = PluginRegistry()
        # 'json' module has no register() function
        with pytest.raises(AttributeError, match="register"):
            reg.load_plugin("json")

    def test_empty_registry(self) -> None:
        reg = PluginRegistry()
        assert reg.plugins == []
        assert reg.packet_hooks == []
        assert reg.event_hooks == []
        # apply with no hooks should return packet unchanged
        pkt = _make_packet()
        assert reg.apply_packet_hooks(pkt, "x") is pkt
