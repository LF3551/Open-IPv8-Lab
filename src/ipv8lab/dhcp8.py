# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""DHCP8 lease simulation per draft-thain-ipv8-00 Section 1.3.

A device connecting to an IPv8 network sends one DHCP8 Discover and
receives one response containing every service endpoint it requires.
No subsequent manual configuration is needed for any service.

The DHCP8 lease delivers:
- IPv8 address assignment
- Default gateways (even/odd pair per Section 17.1)
- Zone Server endpoints (primary .254, secondary .253)
- DNS8 server
- NTP8 server
- NetLog8 endpoint
- OAuth8 cache endpoint
- Management VRF (VLAN 4090) and OOB VRF (VLAN 4091)
- Lease duration
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum, auto

from ipv8lab.address import IPv8Address


class DHCP8MessageType(Enum):
    """DHCP8 message types."""

    DISCOVER = auto()
    OFFER = auto()
    REQUEST = auto()
    ACK = auto()
    NAK = auto()
    RELEASE = auto()


@dataclass(frozen=True, slots=True)
class DHCP8ServiceEndpoints:
    """All service endpoints delivered in a single DHCP8 lease."""

    dns8: str = ""
    ntp8: str = ""
    netlog8: str = ""
    oauth8_cache: str = ""
    zone_server_primary: str = ""     # .254
    zone_server_secondary: str = ""   # .253


@dataclass(frozen=True, slots=True)
class DHCP8Lease:
    """A DHCP8 lease assignment."""

    address: IPv8Address
    gateway_even: IPv8Address
    gateway_odd: IPv8Address
    subnet_prefix: int = 24
    lease_duration: int = 86400  # seconds
    mgmt_vlan: int = 4090
    oob_vlan: int = 4091
    services: DHCP8ServiceEndpoints = field(default_factory=DHCP8ServiceEndpoints)
    issued_at: float = 0.0

    @property
    def expires_at(self) -> float:
        return self.issued_at + self.lease_duration

    def is_expired(self, now: float | None = None) -> bool:
        if now is None:
            now = time.monotonic()
        return now >= self.expires_at


@dataclass
class DHCP8Pool:
    """Address pool for DHCP8 lease allocation."""

    zone_prefix: tuple[int, int, int, int]
    network_prefix: tuple[int, int, int]  # first 3 octets of n.n.n.n
    start: int = 10   # first host octet
    end: int = 249     # last host octet (250-254 reserved)
    _next: int = -1

    def __post_init__(self) -> None:
        if self._next == -1:
            self._next = self.start

    @property
    def available(self) -> int:
        return max(0, self.end - self._next + 1)

    def allocate(self) -> IPv8Address | None:
        """Allocate the next available address from the pool."""
        if self._next > self.end:
            return None
        host = (
            self.network_prefix[0],
            self.network_prefix[1],
            self.network_prefix[2],
            self._next,
        )
        addr = IPv8Address(routing_prefix=self.zone_prefix, host_part=host)
        self._next += 1
        return addr

    def reset(self) -> None:
        self._next = self.start


@dataclass
class DHCP8Server:
    """Mock DHCP8 server.

    Delivers every service endpoint in a single lease response.
    """

    pool: DHCP8Pool
    services: DHCP8ServiceEndpoints = field(default_factory=DHCP8ServiceEndpoints)
    lease_duration: int = 86400
    _leases: dict[str, DHCP8Lease] = field(default_factory=dict)
    _clock: object = field(default=None)

    def __post_init__(self) -> None:
        if self._clock is None:
            self._clock = time.monotonic

    def _make_gateways(self) -> tuple[IPv8Address, IPv8Address]:
        """Create even/odd default gateway pair (.254 and .253)."""
        rp = self.pool.zone_prefix
        np = self.pool.network_prefix
        even = IPv8Address(routing_prefix=rp, host_part=(np[0], np[1], np[2], 254))
        odd = IPv8Address(routing_prefix=rp, host_part=(np[0], np[1], np[2], 253))
        return even, odd

    def discover(self, client_id: str) -> DHCP8Lease | None:
        """Process a DHCP8 Discover → return an Offer/ACK lease.

        One response contains every service endpoint.
        """
        # Check for existing active lease
        existing = self._leases.get(client_id)
        now: float = self._clock()  # type: ignore[operator]
        if existing is not None and not existing.is_expired(now):
            return existing

        addr = self.pool.allocate()
        if addr is None:
            return None

        gw_even, gw_odd = self._make_gateways()

        lease = DHCP8Lease(
            address=addr,
            gateway_even=gw_even,
            gateway_odd=gw_odd,
            lease_duration=self.lease_duration,
            services=self.services,
            issued_at=now,
        )
        self._leases[client_id] = lease
        return lease

    def release(self, client_id: str) -> bool:
        """Release a lease."""
        if client_id in self._leases:
            del self._leases[client_id]
            return True
        return False

    def get_lease(self, client_id: str) -> DHCP8Lease | None:
        return self._leases.get(client_id)

    @property
    def active_leases(self) -> int:
        return len(self._leases)
