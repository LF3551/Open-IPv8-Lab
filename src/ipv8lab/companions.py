# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Companion spec module stubs per draft-thain-ipv8-00.

Models data structures and basic behaviours from companion
specifications referenced in the core IPv8 spec:

- draft-thain-routing-protocols-00: BGP8, IBGP8, OSPF8, IS-IS8
- draft-thain-rine-00: Regional Inter-Network Exchange
- draft-thain-support8-00: ARP8, Route8
- draft-thain-zoneserver-00: XLATE8 translation
- draft-thain-update8-00: Update8 and NIC certification
- draft-thain-wifi8-00: WiFi8 protocol
- draft-thain-ipv8-mib-00: SNMPv8 MIB
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum, auto


# ===================================================================
# draft-thain-routing-protocols-00 — BGP8, IBGP8, OSPF8, IS-IS8
# ===================================================================

class BGP8State(Enum):
    """BGP8 peer FSM states per RFC 4271 extended for IPv8."""

    IDLE = auto()
    CONNECT = auto()
    ACTIVE = auto()
    OPEN_SENT = auto()
    OPEN_CONFIRM = auto()
    ESTABLISHED = auto()


@dataclass(frozen=True, slots=True)
class BGP8Peer:
    """An eBGP8 or iBGP8 peer."""

    asn: int
    address: str       # IPv8 address string
    is_ebgp: bool = True
    state: BGP8State = BGP8State.IDLE
    description: str = ""


@dataclass(frozen=True, slots=True)
class BGP8Advertisement:
    """A BGP8 route advertisement.

    Section 8.3: minimum injectable prefix is /16 for eBGP8.
    The 8TO4-ENDPOINT attribute carries the IPv4 tunnel endpoint.
    """

    prefix: str          # e.g. "64496.0.0.0.0/8"
    origin_asn: int
    as_path: tuple[int, ...] = ()
    next_hop: str = ""
    cf_accumulated: float = 0.0   # CF metric from [ROUTING-PROTOCOLS]
    tunnel_endpoint: str = ""     # 8TO4-ENDPOINT BGP8 attribute
    prefix_length: int = 8

    def is_valid_ebgp_prefix(self) -> bool:
        """Section 8.3 / 18.7: /16 minimum for eBGP8."""
        return self.prefix_length <= 16


class BGP8Table:
    """BGP8 Adj-RIB-In / Loc-RIB."""

    def __init__(self) -> None:
        self._entries: dict[str, BGP8Advertisement] = {}

    def install(self, adv: BGP8Advertisement) -> bool:
        """Install advertisement if valid.  Returns False on /16 violation."""
        if not adv.is_valid_ebgp_prefix():
            return False
        self._entries[adv.prefix] = adv
        return True

    def withdraw(self, prefix: str) -> bool:
        if prefix in self._entries:
            del self._entries[prefix]
            return True
        return False

    def lookup(self, prefix: str) -> BGP8Advertisement | None:
        return self._entries.get(prefix)

    def best_path(self, prefix: str) -> BGP8Advertisement | None:
        """Select best path by lowest CF (simplified)."""
        return self._entries.get(prefix)

    @property
    def size(self) -> int:
        return len(self._entries)

    def entries(self) -> list[BGP8Advertisement]:
        return list(self._entries.values())


class OSPF8AreaType(Enum):
    """OSPF8 area types per [ROUTING-PROTOCOLS] Section 10.3."""

    NORMAL = auto()
    STUB = auto()
    NSSA = auto()
    BACKBONE = auto()  # Area 0


@dataclass(frozen=True, slots=True)
class OSPF8Area:
    """An OSPF8 routing area."""

    area_id: int
    area_type: OSPF8AreaType = OSPF8AreaType.NORMAL
    description: str = ""

    @property
    def is_backbone(self) -> bool:
        return self.area_id == 0 or self.area_type == OSPF8AreaType.BACKBONE


@dataclass(frozen=True, slots=True)
class OSPF8LSA:
    """OSPF8 Link State Advertisement."""

    lsa_type: int      # 1=Router, 2=Network, 3=Summary, etc.
    link_state_id: str
    advertising_router: str
    sequence_number: int = 1
    cf_export: float = 0.0  # CF export interface per Section 8.5


class ISIS8Level(Enum):
    """IS-IS8 levels."""

    L1 = auto()
    L2 = auto()
    L1_L2 = auto()


@dataclass(frozen=True, slots=True)
class ISIS8Adjacency:
    """IS-IS8 adjacency per [ROUTING-PROTOCOLS] Section 10.4."""

    system_id: str
    level: ISIS8Level = ISIS8Level.L1_L2
    metric: int = 10
    state: str = "Up"


# ===================================================================
# draft-thain-rine-00 — Regional Inter-Network Exchange
# ===================================================================

@dataclass(frozen=True, slots=True)
class RINEPeeringLink:
    """A RINE peering link between two ASNs.

    Section 3.9: 100.0.0.0/8 reserved for RINE peering fabric.
    RINE addresses MUST NOT be globally routed.
    """

    local_asn: int
    remote_asn: int
    local_address: str     # 100.x.x.x address
    remote_address: str    # 100.x.x.x address
    ixp_name: str = ""

    def is_valid_rine_address(self, addr: str) -> bool:
        """Check if address is in 100.0.0.0/8 range."""
        parts = addr.split(".")
        if len(parts) < 4:
            return False
        return parts[0] == "100"


class RINEFabric:
    """RINE peering fabric manager."""

    def __init__(self) -> None:
        self._links: list[RINEPeeringLink] = []

    def add_link(self, link: RINEPeeringLink) -> None:
        self._links.append(link)

    def remove_link(self, index: int) -> RINEPeeringLink:
        return self._links.pop(index)

    def find_peers(self, asn: int) -> list[RINEPeeringLink]:
        return [lnk for lnk in self._links
                if lnk.local_asn == asn or lnk.remote_asn == asn]

    @property
    def link_count(self) -> int:
        return len(self._links)


# ===================================================================
# draft-thain-support8-00 — ARP8, Route8
# ===================================================================

@dataclass(slots=True)
class ARP8Entry:
    """ARP8 cache entry.

    Section 17.1: gratuitous ARP8 on boot is mandatory for Tier 1.
    """

    ipv8_address: str
    mac_address: str
    is_gratuitous: bool = False
    timestamp: float = 0.0
    vlan: int = 0

    def is_expired(self, now: float, ttl: float = 14400.0) -> bool:
        """Default ARP cache TTL = 4 hours."""
        return now - self.timestamp >= ttl


class ARP8Table:
    """ARP8 cache table."""

    def __init__(self) -> None:
        self._entries: dict[str, ARP8Entry] = {}

    def learn(self, entry: ARP8Entry) -> None:
        self._entries[entry.ipv8_address] = entry

    def lookup(self, ipv8_address: str) -> ARP8Entry | None:
        return self._entries.get(ipv8_address)

    def flush(self) -> int:
        count = len(self._entries)
        self._entries.clear()
        return count

    def flush_expired(self, now: float, ttl: float = 14400.0) -> int:
        expired = [k for k, v in self._entries.items() if v.is_expired(now, ttl)]
        for k in expired:
            del self._entries[k]
        return len(expired)

    def gratuitous_announce(self, ipv8_address: str, mac_address: str) -> ARP8Entry:
        """Gratuitous ARP8 per Section 17.1."""
        entry = ARP8Entry(
            ipv8_address=ipv8_address,
            mac_address=mac_address,
            is_gratuitous=True,
            timestamp=time.time(),
        )
        self._entries[ipv8_address] = entry
        return entry

    @property
    def size(self) -> int:
        return len(self._entries)


# ===================================================================
# draft-thain-zoneserver-00 — XLATE8 translation
# ===================================================================

@dataclass(frozen=True, slots=True)
class XLATE8Entry:
    """XLATE8 translation table entry.

    Section 1.4: north-south egress requires DNS8 lookup → XLATE8
    state table entry.  No DNS lookup = no XLATE8 entry = blocked.
    """

    internal_address: str   # 127.x.x.x.n.n.n.n
    external_address: str   # <asn>.n.n.n.n
    protocol: int = 6       # TCP
    internal_port: int = 0
    external_port: int = 0
    dns_validated: bool = True
    created_at: float = 0.0


class XLATE8Table:
    """XLATE8 translation table (Zone Server egress)."""

    def __init__(self) -> None:
        self._entries: dict[str, XLATE8Entry] = {}

    def create_entry(self, entry: XLATE8Entry) -> bool:
        """Create translation entry.  Requires dns_validated=True."""
        if not entry.dns_validated:
            return False
        key = f"{entry.internal_address}:{entry.internal_port}"
        self._entries[key] = entry
        return True

    def lookup_internal(self, address: str, port: int) -> XLATE8Entry | None:
        return self._entries.get(f"{address}:{port}")

    def remove(self, address: str, port: int) -> bool:
        key = f"{address}:{port}"
        if key in self._entries:
            del self._entries[key]
            return True
        return False

    @property
    def size(self) -> int:
        return len(self._entries)

    def entries(self) -> list[XLATE8Entry]:
        return list(self._entries.values())


# ===================================================================
# draft-thain-update8-00 — Update8 and NIC certification
# ===================================================================

class Update8Status(Enum):
    """Update8 package status."""

    AVAILABLE = auto()
    DOWNLOADING = auto()
    VALIDATING = auto()
    READY = auto()
    APPLIED = auto()
    FAILED = auto()
    ROLLED_BACK = auto()


@dataclass(frozen=True, slots=True)
class Update8Package:
    """An Update8 firmware/software package.

    Section 17.5: updates from DNS-named sources only.
    Connection to update source by IP address is blocked.
    """

    package_id: str
    vendor: str
    version: str
    source_dns: str     # DNS-named source (not IP)
    component: str      # e.g. "nic-firmware", "l3-stack"
    size_bytes: int = 0
    signature: str = ""
    status: Update8Status = Update8Status.AVAILABLE

    def is_dns_source(self) -> bool:
        """Validate source is DNS name, not IP address."""
        parts = self.source_dns.split(".")
        # Simple check: if all parts are digits, it's an IP
        return not all(p.isdigit() for p in parts)


class NICCertLevel(Enum):
    """NIC certification levels per [UPDATE8]."""

    UNCERTIFIED = auto()
    LEVEL_1 = auto()  # Basic rate limiting
    LEVEL_2 = auto()  # Full ACL8 enforcement
    LEVEL_3 = auto()  # Full Update8 + rollback prevention


@dataclass(frozen=True, slots=True)
class NICCertification:
    """NIC certification status."""

    vendor: str
    model: str
    firmware_version: str
    cert_level: NICCertLevel = NICCertLevel.UNCERTIFIED
    rate_limit_enforced: bool = False
    acl8_enforced: bool = False
    rollback_prevention: bool = False


# ===================================================================
# draft-thain-wifi8-00 — WiFi8 Protocol
# ===================================================================

class WiFi8Band(Enum):
    """WiFi8 frequency bands."""

    BAND_2_4GHZ = auto()
    BAND_5GHZ = auto()
    BAND_6GHZ = auto()


@dataclass(frozen=True, slots=True)
class WiFi8AccessPoint:
    """WiFi8 access point with Zone Server integration."""

    ssid: str
    bssid: str
    band: WiFi8Band = WiFi8Band.BAND_5GHZ
    zone_server_address: str = ""
    oauth8_required: bool = True
    vlan_id: int = 0


# ===================================================================
# draft-thain-ipv8-mib-00 — SNMPv8 MIB
# ===================================================================

@dataclass(frozen=True, slots=True)
class SNMPv8OID:
    """An SNMPv8 MIB object identifier."""

    oid: str
    name: str
    value_type: str = "Integer32"
    description: str = ""


class SNMPv8MIB:
    """IPv8 MIB tree (simplified)."""

    def __init__(self) -> None:
        self._objects: dict[str, SNMPv8OID] = {}

    def register(self, obj: SNMPv8OID) -> None:
        self._objects[obj.oid] = obj

    def get(self, oid: str) -> SNMPv8OID | None:
        return self._objects.get(oid)

    def walk(self, prefix: str = "") -> list[SNMPv8OID]:
        """SNMP walk: return all OIDs starting with prefix."""
        if not prefix:
            return list(self._objects.values())
        return [o for o in self._objects.values() if o.oid.startswith(prefix)]

    @property
    def size(self) -> int:
        return len(self._objects)
