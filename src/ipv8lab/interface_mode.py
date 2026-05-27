# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Per-interface IPv8 operating mode per spec §7.7.1.

Each physical or virtual interface on an IPv8-aware host operates in
exactly one of four modes. The mode is immutable for the lifetime of a
DHCP8 session; changing it requires an interface reset (new session id).

Mode semantics
--------------
NORMAL
    Default mode.  No additional access restrictions beyond the normal
    IPv8 forwarding rules.

STRICT
    The interface maintains a per-interface DNS-resolution cache.
    Outbound packets to a destination not present in the cache (i.e. no
    recent A8/AAAA resolution for that LA) are dropped and a NetLog8
    E-class event is emitted.

PNP (formerly "printer" in earlier drafts)
    Plug-and-Play service mode.  The interface is registered with the
    segment ACL server and is permitted to join mDNS/SSDP/WS-Discovery/
    LLMNR multicast groups.  Inbound unicast is only accepted from
    addresses that have resolved the service via one of those protocols.

GUEST
    Restricted mode.  The interface may only reach destinations whose
    RN is 0 (public IPv4-compatible internet) or published PNP services
    on the segment.  All other destinations are silently dropped.

Wire encoding
-------------
The mode is carried in **DHCP8 option 223** as a single unsigned byte:
    0 = NORMAL, 1 = STRICT, 2 = PNP, 3 = GUEST

DHCP8 option 222 carries the segment's **Primary RN** as a 4-byte
big-endian unsigned integer (the raw :attr:`~ipv8lab.address.IPv8Address.rn`
value).

Backwards compatibility
-----------------------
The name "PRINTER" from earlier internal drafts is provided as a
deprecated alias for ``PNP``.
"""

from __future__ import annotations

import warnings
from enum import IntEnum


class InterfaceMode(IntEnum):
    """Per-interface IPv8 operating mode (spec §7.7.1)."""

    NORMAL = 0
    STRICT = 1
    PNP = 2
    GUEST = 3

    @classmethod
    def from_wire(cls, byte: int) -> "InterfaceMode":
        """Decode a single wire byte to an InterfaceMode."""
        try:
            return cls(byte)
        except ValueError:
            raise ValueError(f"Unknown InterfaceMode wire value: {byte!r}") from None

    def to_wire(self) -> int:
        """Encode to a single wire byte."""
        return int(self)


def _printer_alias() -> InterfaceMode:  # pragma: no cover
    warnings.warn(
        "InterfaceMode.PRINTER is deprecated; use InterfaceMode.PNP.",
        DeprecationWarning,
        stacklevel=3,
    )
    return InterfaceMode.PNP


# Backwards-compat alias — access as InterfaceMode.PRINTER
InterfaceMode.PRINTER = InterfaceMode.PNP  # type: ignore[attr-defined]


# DHCP8 option codes
DHCP8_OPT_PRIMARY_RN = 222   # 4-byte big-endian unsigned int
DHCP8_OPT_IFACE_MODE = 223   # 1 byte (InterfaceMode wire value)
