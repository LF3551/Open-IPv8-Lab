# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Multicast and broadcast handling per draft-thain-ipv8-00 Sections 10-12.

Cross-ASN multicast prefixes (ff.ff.xx.xx):
  ff.ff.00.00  General cross-ASN multicast
  ff.ff.00.01  OSPF8 protocol traffic
  ff.ff.00.02  BGP8 peer discovery
  ff.ff.00.03  EIGRP (reserved, deprecated)
  ff.ff.00.04  RIP (reserved, deprecated)
  ff.ff.00.05  IS-IS8 (reserved, vendor ext.)

Multicast group assignments (ff.ff.00.00.224.0.0.x):
  224.0.0.1   All IPv8 routers
  224.0.0.2   All IPv8 Zone Servers
  224.0.0.5   OSPF8 all routers
  224.0.0.6   OSPF8 designated routers
  224.0.0.10  IBGP8 peer discovery
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from ipv8lab.address import IPv8Address


class MulticastType(str, Enum):
    """Type of multicast address."""

    INTRA_ASN = "intra-asn"
    CROSS_ASN_GENERAL = "cross-asn-general"
    OSPF8 = "ospf8"
    BGP8 = "bgp8"
    EIGRP_DEPRECATED = "eigrp-deprecated"
    RIP_DEPRECATED = "rip-deprecated"
    ISIS8 = "is-is8"
    UNKNOWN_PROTOCOL = "unknown-protocol"
    NOT_MULTICAST = "not-multicast"


# Cross-ASN protocol multicast prefix → type mapping
_CROSS_ASN_PROTOCOL_MAP: dict[tuple[int, int, int, int], MulticastType] = {
    (255, 255, 0, 0): MulticastType.CROSS_ASN_GENERAL,
    (255, 255, 0, 1): MulticastType.OSPF8,
    (255, 255, 0, 2): MulticastType.BGP8,
    (255, 255, 0, 3): MulticastType.EIGRP_DEPRECATED,
    (255, 255, 0, 4): MulticastType.RIP_DEPRECATED,
    (255, 255, 0, 5): MulticastType.ISIS8,
}

# Well-known multicast group addresses (n.n.n.n part)
MULTICAST_ALL_ROUTERS = (224, 0, 0, 1)
MULTICAST_ALL_ZONE_SERVERS = (224, 0, 0, 2)
MULTICAST_OSPF8_ALL_ROUTERS = (224, 0, 0, 5)
MULTICAST_OSPF8_DESIGNATED = (224, 0, 0, 6)
MULTICAST_IBGP8_DISCOVERY = (224, 0, 0, 10)

_WELL_KNOWN_GROUPS: dict[tuple[int, int, int, int], str] = {
    MULTICAST_ALL_ROUTERS: "All IPv8 routers",
    MULTICAST_ALL_ZONE_SERVERS: "All IPv8 Zone Servers",
    MULTICAST_OSPF8_ALL_ROUTERS: "OSPF8 all routers",
    MULTICAST_OSPF8_DESIGNATED: "OSPF8 designated routers",
    MULTICAST_IBGP8_DISCOVERY: "IBGP8 peer discovery",
}


def classify_multicast(addr: IPv8Address) -> MulticastType:
    """Classify a multicast address by type."""
    if addr.is_broadcast():
        return MulticastType.NOT_MULTICAST
    if addr.is_intra_asn_multicast():
        return MulticastType.INTRA_ASN
    if addr.is_multicast():
        return _CROSS_ASN_PROTOCOL_MAP.get(
            addr.routing_prefix, MulticastType.UNKNOWN_PROTOCOL
        )
    return MulticastType.NOT_MULTICAST


def multicast_group_name(addr: IPv8Address) -> str | None:
    """Return the well-known group name for a multicast address, if any."""
    return _WELL_KNOWN_GROUPS.get(addr.host_part)


def is_deprecated_protocol(addr: IPv8Address) -> bool:
    """True if the address uses a deprecated multicast protocol prefix."""
    mc_type = classify_multicast(addr)
    return mc_type in (MulticastType.EIGRP_DEPRECATED, MulticastType.RIP_DEPRECATED)


@dataclass(frozen=True, slots=True)
class MulticastInfo:
    """Full multicast classification result."""

    address: IPv8Address
    multicast_type: MulticastType
    group_name: str | None
    routable_beyond_as: bool
    deprecated: bool


def analyze_multicast(addr: IPv8Address) -> MulticastInfo:
    """Full analysis of a multicast address."""
    mc_type = classify_multicast(addr)
    group_name = multicast_group_name(addr)
    routable = mc_type != MulticastType.INTRA_ASN and mc_type != MulticastType.NOT_MULTICAST
    deprecated = is_deprecated_protocol(addr)
    return MulticastInfo(
        address=addr,
        multicast_type=mc_type,
        group_name=group_name,
        routable_beyond_as=routable,
        deprecated=deprecated,
    )
