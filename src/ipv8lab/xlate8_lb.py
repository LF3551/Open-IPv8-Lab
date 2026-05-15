# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""XLATE8 Even/Odd Load Balancing per draft-thain-ipv8-02 Section 15.1.

When an IPv4 client connects to an IPv8 host via an XLATE8 gateway,
the destination host may have both an even and an odd A8 address.

- The gateway SHOULD pass both addresses through where the client is
  capable of using both.
- Where the client is NOT capable, the gateway MAY perform load
  balancing internally, distributing connections across even and odd
  addresses of the destination host.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from ipv8lab.address import IPv8Address


# ---------------------------------------------------------------------------
# Even/Odd classification
# ---------------------------------------------------------------------------

class Parity(str, Enum):
    EVEN = "even"
    ODD = "odd"


def address_parity(addr: IPv8Address) -> Parity:
    """Determine parity of the host address (last octet)."""
    return Parity.EVEN if addr.host_part[3] % 2 == 0 else Parity.ODD


@dataclass(frozen=True, slots=True)
class A8Pair:
    """An even/odd A8 address pair for a single host (Section 1.4)."""

    even: IPv8Address
    odd: IPv8Address

    def to_dict(self) -> dict[str, str]:
        return {"even": self.even.full_notation, "odd": self.odd.full_notation}


def make_a8_pair(asn: int, host_base: str) -> A8Pair:
    """Create an even/odd A8 pair.

    *host_base* is a dotted quad like ``10.0.0.``; the last octet is
    set to produce one even and one odd address.
    """
    parts = host_base.rstrip(".").split(".")
    if len(parts) != 3:
        msg = f"host_base must be 3 octets (e.g. '10.0.0'), got {host_base!r}"
        raise ValueError(msg)
    prefix = ".".join(parts)
    even_addr = IPv8Address.parse(f"{asn}.{prefix}.2")
    odd_addr = IPv8Address.parse(f"{asn}.{prefix}.3")
    return A8Pair(even=even_addr, odd=odd_addr)


# ---------------------------------------------------------------------------
# LB strategy
# ---------------------------------------------------------------------------

class LBStrategy(str, Enum):
    PASSTHROUGH = "passthrough"   # pass both addresses to capable client
    ROUND_ROBIN = "round_robin"  # alternate even/odd per connection
    EVEN_ONLY = "even_only"
    ODD_ONLY = "odd_only"


# ---------------------------------------------------------------------------
# Connection record
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class LBConnection:
    """One load-balanced connection."""

    client_addr: str
    client_port: int
    selected: IPv8Address
    parity: Parity
    seq: int


# ---------------------------------------------------------------------------
# XLATE8 Even/Odd Load Balancer
# ---------------------------------------------------------------------------

@dataclass
class EvenOddLB:
    """XLATE8 Even/Odd load balancer per Section 15.1.

    Parameters:
        pair:     The A8 even/odd address pair of the destination host.
        strategy: Load balancing strategy when client cannot use both.
    """

    pair: A8Pair
    strategy: LBStrategy = LBStrategy.ROUND_ROBIN
    _counter: int = field(default=0, init=False)
    _connections: list[LBConnection] = field(default_factory=list, init=False)

    def select(self, client_addr: str = "0.0.0.0", client_port: int = 0) -> LBConnection:
        """Select the next destination address for an incoming connection."""
        if self.strategy == LBStrategy.PASSTHROUGH:
            # Passthrough: alternate but both are "visible"
            chosen = self.pair.even if self._counter % 2 == 0 else self.pair.odd
        elif self.strategy == LBStrategy.EVEN_ONLY:
            chosen = self.pair.even
        elif self.strategy == LBStrategy.ODD_ONLY:
            chosen = self.pair.odd
        else:
            # Round-robin (default)
            chosen = self.pair.even if self._counter % 2 == 0 else self.pair.odd

        parity = address_parity(chosen)
        conn = LBConnection(
            client_addr=client_addr,
            client_port=client_port,
            selected=chosen,
            parity=parity,
            seq=self._counter,
        )
        self._connections.append(conn)
        self._counter += 1
        return conn

    def distribute(
        self,
        client_addr: str,
        count: int,
    ) -> list[LBConnection]:
        """Simulate *count* connections from *client_addr*."""
        return [
            self.select(client_addr=client_addr, client_port=10000 + i)
            for i in range(count)
        ]

    @property
    def connections(self) -> list[LBConnection]:
        return list(self._connections)

    @property
    def stats(self) -> dict[str, int]:
        even_n = sum(1 for c in self._connections if c.parity == Parity.EVEN)
        odd_n = len(self._connections) - even_n
        return {"total": len(self._connections), "even": even_n, "odd": odd_n}

    def reset(self) -> None:
        self._connections.clear()
        self._counter = 0

    def summary(self) -> dict[str, object]:
        return {
            "pair": self.pair.to_dict(),
            "strategy": self.strategy.value,
            "stats": self.stats,
        }
