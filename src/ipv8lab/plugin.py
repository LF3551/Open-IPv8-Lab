# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Simple plugin system for IPv8 Lab.

Plugins are Python modules that expose a ``register(registry)`` function.
The registry provides hooks for extending simulator behaviour.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import Any, Callable

from ipv8lab.packet import IPv8Packet

# Hook type aliases
PacketHook = Callable[[IPv8Packet, str], IPv8Packet | None]
"""Called when a packet arrives at a node.  Return the packet to continue
processing, or ``None`` to drop it."""

EventHook = Callable[[str, dict[str, Any]], None]
"""Called on simulation events (e.g. 'node_added', 'link_created')."""


@dataclass(slots=True)
class PluginInfo:
    """Metadata about a registered plugin."""

    name: str
    version: str = "0.0.0"
    description: str = ""


class PluginRegistry:
    """Central registry for plugins and hooks."""

    def __init__(self) -> None:
        self._plugins: list[PluginInfo] = []
        self._packet_hooks: list[PacketHook] = []
        self._event_hooks: list[EventHook] = []

    @property
    def plugins(self) -> list[PluginInfo]:
        return list(self._plugins)

    @property
    def packet_hooks(self) -> list[PacketHook]:
        return list(self._packet_hooks)

    @property
    def event_hooks(self) -> list[EventHook]:
        return list(self._event_hooks)

    def register_plugin(self, info: PluginInfo) -> None:
        """Register plugin metadata."""
        self._plugins.append(info)

    def add_packet_hook(self, hook: PacketHook) -> None:
        """Add a hook that processes packets at each node."""
        self._packet_hooks.append(hook)

    def add_event_hook(self, hook: EventHook) -> None:
        """Add a hook for simulation events."""
        self._event_hooks.append(hook)

    def apply_packet_hooks(self, packet: IPv8Packet, node_name: str) -> IPv8Packet | None:
        """Run all packet hooks in order. Returns None if any hook drops the packet."""
        current: IPv8Packet | None = packet
        for hook in self._packet_hooks:
            if current is None:
                return None
            current = hook(current, node_name)
        return current

    def emit_event(self, event: str, data: dict[str, Any] | None = None) -> None:
        """Emit an event to all event hooks."""
        for hook in self._event_hooks:
            hook(event, data or {})

    def load_plugin(self, module_path: str) -> None:
        """Load a plugin by Python module path (e.g. 'mypackage.myplugin').

        The module must have a ``register(registry)`` function.
        """
        mod = importlib.import_module(module_path)
        register_fn = getattr(mod, "register", None)
        if register_fn is None:
            msg = f"Plugin module {module_path!r} has no register() function"
            raise AttributeError(msg)
        register_fn(self)
