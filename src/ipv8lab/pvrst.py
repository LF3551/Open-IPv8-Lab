# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""PVRST per draft-thain-ipv8- Section 17.4.

Per-VLAN Rapid Spanning Tree is mandatory for all IPv8 L2 and L3 devices.
MST is not recommended.

Zone Servers are PVRST roots by default:
  - Primary Zone Server (.254): root for even VLANs, priority 4096
  - Secondary Zone Server (.253): root for odd VLANs, priority 4096
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto


class ZoneServerRole(Enum):
    """Zone Server role in PVRST."""

    PRIMARY = auto()    # .254 — even VLANs
    SECONDARY = auto()  # .253 — odd VLANs


# Section 17.4 constants
PRIMARY_HOST_OCTET = 254
SECONDARY_HOST_OCTET = 253
ROOT_PRIORITY = 4096
DEFAULT_PRIORITY = 32768


@dataclass(frozen=True, slots=True)
class PVRSTConfig:
    """PVRST configuration for a device."""

    priority: int = DEFAULT_PRIORITY
    zone_server_role: ZoneServerRole | None = None

    def is_root_for_vlan(self, vlan_id: int) -> bool:
        """Check if this device should be PVRST root for a given VLAN."""
        if self.zone_server_role is None:
            return False
        if self.priority != ROOT_PRIORITY:
            return False
        if self.zone_server_role == ZoneServerRole.PRIMARY:
            return vlan_id % 2 == 0
        return vlan_id % 2 == 1

    def root_vlans(self, vlan_range: range | None = None) -> list[int]:
        """Return list of VLANs this device is root for."""
        if vlan_range is None:
            vlan_range = range(1, 4095)
        return [v for v in vlan_range if self.is_root_for_vlan(v)]


@dataclass
class PVRSTBridge:
    """A bridge participating in PVRST."""

    bridge_id: str
    config: PVRSTConfig = field(default_factory=PVRSTConfig)
    _port_states: dict[int, dict[int, str]] = field(default_factory=dict)

    def set_port_state(self, vlan_id: int, port: int, state: str) -> None:
        """Set port state for a VLAN (forwarding/blocking/learning/disabled)."""
        valid = {"forwarding", "blocking", "learning", "listening", "disabled"}
        if state not in valid:
            msg = f"Invalid port state '{state}', must be one of {valid}"
            raise ValueError(msg)
        self._port_states.setdefault(vlan_id, {})[port] = state

    def get_port_state(self, vlan_id: int, port: int) -> str:
        """Get port state for a VLAN. Default is blocking."""
        return self._port_states.get(vlan_id, {}).get(port, "blocking")


def make_primary_zone_server(bridge_id: str) -> PVRSTBridge:
    """Create a primary Zone Server (.254) with PVRST root config."""
    return PVRSTBridge(
        bridge_id=bridge_id,
        config=PVRSTConfig(
            priority=ROOT_PRIORITY,
            zone_server_role=ZoneServerRole.PRIMARY,
        ),
    )


def make_secondary_zone_server(bridge_id: str) -> PVRSTBridge:
    """Create a secondary Zone Server (.253) with PVRST root config."""
    return PVRSTBridge(
        bridge_id=bridge_id,
        config=PVRSTConfig(
            priority=ROOT_PRIORITY,
            zone_server_role=ZoneServerRole.SECONDARY,
        ),
    )


def elect_root(bridges: list[PVRSTBridge], vlan_id: int) -> PVRSTBridge | None:
    """Elect PVRST root for a VLAN — lowest priority wins, Zone Server role preferred."""
    if not bridges:
        return None
    candidates = sorted(bridges, key=lambda b: (b.config.priority, b.bridge_id))
    # Prefer bridge that is designated root for this VLAN
    for b in candidates:
        if b.config.is_root_for_vlan(vlan_id):
            return b
    return candidates[0]
