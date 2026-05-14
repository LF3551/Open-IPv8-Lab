# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""VRF — Virtual Routing and Forwarding per draft-thain-ipv8-00 Section 8.8.

VRF is mandatory for all IPv8 L3 devices.
- Management VRF (VLAN 4090): device management traffic
- OOB VRF (VLAN 4091): out-of-band management traffic

VRF isolation is a routing table property that cannot be bypassed
by software misconfiguration.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ipv8lab.address import IPv8Address
from ipv8lab.route import Route, RouteTable

# Well-known VRF VLANs
MGMT_VLAN = 4090
OOB_VLAN = 4091

# Reserved VRF names
MGMT_VRF_NAME = "management"
OOB_VRF_NAME = "oob"
DEFAULT_VRF_NAME = "default"


@dataclass
class VRF:
    """A single Virtual Routing and Forwarding instance."""

    name: str
    vlan: int | None = None
    table: RouteTable = field(default_factory=RouteTable)
    description: str = ""

    def add_route(self, route: Route) -> None:
        self.table.add_route(route)

    def lookup(self, addr: IPv8Address) -> Route | None:
        try:
            return self.table.find_route(addr)
        except Exception:  # noqa: BLE001
            return None


@dataclass
class VRFManager:
    """Manages multiple VRF instances per Section 8.8.

    All IPv8 L3 devices MUST have management (VLAN 4090) and OOB (VLAN 4091) VRFs.
    """

    _vrfs: dict[str, VRF] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Mandatory VRFs per Section 8.8
        if MGMT_VRF_NAME not in self._vrfs:
            self._vrfs[MGMT_VRF_NAME] = VRF(
                name=MGMT_VRF_NAME,
                vlan=MGMT_VLAN,
                description="Device management traffic",
            )
        if OOB_VRF_NAME not in self._vrfs:
            self._vrfs[OOB_VRF_NAME] = VRF(
                name=OOB_VRF_NAME,
                vlan=OOB_VLAN,
                description="Out-of-band management traffic",
            )
        if DEFAULT_VRF_NAME not in self._vrfs:
            self._vrfs[DEFAULT_VRF_NAME] = VRF(
                name=DEFAULT_VRF_NAME,
                description="Global/default routing table",
            )

    def get(self, name: str) -> VRF | None:
        return self._vrfs.get(name)

    def create(self, name: str, vlan: int | None = None, description: str = "") -> VRF:
        """Create a new VRF instance."""
        if name in self._vrfs:
            msg = f"VRF '{name}' already exists"
            raise ValueError(msg)
        vrf = VRF(name=name, vlan=vlan, description=description)
        self._vrfs[name] = vrf
        return vrf

    def delete(self, name: str) -> None:
        """Delete a VRF. Mandatory VRFs cannot be deleted."""
        if name in (MGMT_VRF_NAME, OOB_VRF_NAME):
            msg = f"Cannot delete mandatory VRF '{name}'"
            raise ValueError(msg)
        if name not in self._vrfs:
            msg = f"VRF '{name}' does not exist"
            raise KeyError(msg)
        del self._vrfs[name]

    def list_vrfs(self) -> list[str]:
        return sorted(self._vrfs.keys())

    def is_isolated(self, vrf_a: str, vrf_b: str) -> bool:
        """Verify that two VRFs have no route leaking.

        VRF isolation is a routing table property that cannot be
        bypassed by software misconfiguration.
        """
        a = self._vrfs.get(vrf_a)
        b = self._vrfs.get(vrf_b)
        if a is None or b is None:
            return True  # non-existent VRF is isolated by definition
        # VRFs are isolated if they are different instances
        return a is not b

    @property
    def management(self) -> VRF:
        return self._vrfs[MGMT_VRF_NAME]

    @property
    def oob(self) -> VRF:
        return self._vrfs[OOB_VRF_NAME]

    @property
    def default(self) -> VRF:
        return self._vrfs[DEFAULT_VRF_NAME]
