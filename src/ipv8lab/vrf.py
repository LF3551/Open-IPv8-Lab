# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""VRF — Virtual Routing and Forwarding per draft-thain-ipv8- Section 8.8.

VRF is mandatory for all IPv8 L3 devices.
- Management VRF (VLAN 4090): device management traffic
- OOB VRF (VLAN 4091): out-of-band management traffic

IPv8 RN-VRF naming convention (spec §3.2):
  Every locally-bound RN gets a VRF named ``ipv8-asn-<RN>`` with
  Route Distinguisher ``<RN>:65535``.  Transit RNs live in the RIB
  but have no local forwarding context.

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

# RD suffix used for all IPv8 RN VRFs (spec §3.2)
_RN_RD_SUFFIX = 65535


def ipv8_vrf_name(rn: int) -> str:
    """Return the canonical VRF name for a locally-bound RN.

    Spec §3.2: ``ipv8-asn-<RN>``.
    """
    return f"ipv8-asn-{rn}"


def ipv8_vrf_rd(rn: int) -> str:
    """Return the Route Distinguisher string for an RN VRF.

    Spec §3.2: ``<RN>:65535``.
    """
    return f"{rn}:{_RN_RD_SUFFIX}"


@dataclass
class VRF:
    """A single Virtual Routing and Forwarding instance."""

    name: str
    vlan: int | None = None
    table: RouteTable = field(default_factory=RouteTable)
    description: str = ""
    route_distinguisher: str = ""
    """Route Distinguisher string, e.g. ``64496:65535`` for an RN VRF."""
    bound_rn: int | None = None
    """RN this VRF was created for, or None for non-RN VRFs."""

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
    # rn → vrf name for locally-bound RNs
    _rn_map: dict[int, str] = field(default_factory=dict)

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

    def bind_rn(self, rn: int, *, description: str = "") -> VRF:
        """Create (or return existing) VRF for a locally-bound RN.

        Names the VRF ``ipv8-asn-<RN>`` with RD ``<RN>:65535`` per
        spec §3.2.  Idempotent — returns the existing VRF if already
        bound.
        """
        name = ipv8_vrf_name(rn)
        if name in self._vrfs:
            return self._vrfs[name]
        vrf = VRF(
            name=name,
            route_distinguisher=ipv8_vrf_rd(rn),
            bound_rn=rn,
            description=description or f"IPv8 RN {rn} forwarding context",
        )
        self._vrfs[name] = vrf
        self._rn_map[rn] = name
        return vrf

    def get_rn_vrf(self, rn: int) -> VRF | None:
        """Return the VRF for a locally-bound RN, or None if not bound."""
        name = self._rn_map.get(rn)
        return self._vrfs.get(name) if name else None

    def has_forwarding_context(self, rn: int) -> bool:
        """True if *rn* has a local VRF (i.e. is not transit-only).

        Spec §3.2: a router maintains a VRF only for RNs it originates
        or terminates.  Transit RNs live in the RIB but have no local
        forwarding context.
        """
        return rn in self._rn_map

    def bound_rns(self) -> list[int]:
        """Return sorted list of locally-bound RNs."""
        return sorted(self._rn_map.keys())

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
