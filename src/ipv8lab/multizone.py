# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Multi-zone simulation with Zone Server pairs.

Models an organisation with multiple internal zones (Section 3.5):
  - 127.1.0.0  Zone 1 (e.g. Americas)
  - 127.2.0.0  Zone 2 (e.g. Europe)
  - 127.3.0.0  Zone 3 (e.g. Asia Pacific)

Each zone has:
  - Zone Server pair (primary .254, secondary .253)
  - DHCP8 server for device provisioning
  - OAuth8 cache + ACL8 engine
  - NetLog8 telemetry client
  - Inter-zone routing via IBGP8 (Tier 1 routes to other zones)

Zone isolation:
  - ACL8 default-deny prevents lateral movement between zones
  - Traffic between zones goes through Zone Server gateways
  - Internal zone addresses (127.x.x.x) MUST NOT be routed externally
"""

from __future__ import annotations

from dataclasses import dataclass

from ipv8lab.address import IPv8Address
from ipv8lab.dhcp8 import DHCP8Lease, DHCP8Pool, DHCP8Server, DHCP8ServiceEndpoints
from ipv8lab.netlog8 import NetLog8Client, NetLog8Facility
from ipv8lab.packet import IPv8Packet
from ipv8lab.route import Route, RouteTable, TwoTierRouteTable
from ipv8lab.whois8 import WHOIS8Resolver
from ipv8lab.zoneserver import (
    ACL8Action,
    ACL8Rule,
    ZoneServer,
    ZoneService,
    ZoneServiceType,
    make_zone_server_pair,
)


@dataclass
class ZoneDefinition:
    """Configuration for a single zone."""

    name: str
    zone_octet: int          # x in 127.x.0.0
    network_prefix: tuple[int, int, int] = (10, 0, 1)
    oauth8_key_id: str = "zone-key"
    oauth8_secret: bytes = b"zone-secret"
    lease_duration: int = 3600

    @property
    def zone_prefix(self) -> str:
        return f"127.{self.zone_octet}.0.0"

    @property
    def zone_prefix_tuple(self) -> tuple[int, int, int, int]:
        return (127, self.zone_octet, 0, 0)


@dataclass
class ZoneInstance:
    """A running zone with all its services."""

    definition: ZoneDefinition
    primary: ZoneServer
    secondary: ZoneServer
    dhcp_server: DHCP8Server
    logger: NetLog8Client
    route_table: TwoTierRouteTable

    @property
    def name(self) -> str:
        return self.definition.name

    @property
    def zone_prefix(self) -> str:
        return self.definition.zone_prefix


@dataclass(frozen=True, slots=True)
class InterZoneLink:
    """A routing link between two zones."""

    source_zone: str
    target_zone: str
    interface: str = "ibgp8-link"


@dataclass(frozen=True, slots=True)
class MultiZoneEvent:
    """An event in the multi-zone simulation."""

    zone: str
    event: str
    success: bool
    detail: str = ""


class MultiZoneSimulation:
    """Multi-zone simulation with Zone Server pairs.

    Creates multiple zones, provisions devices, and routes traffic
    between zones through IBGP8-style inter-zone routing.
    """

    def __init__(self, clock: object | None = None) -> None:
        self._clock = clock
        self._zones: dict[str, ZoneInstance] = {}
        self._links: list[InterZoneLink] = []
        self._whois8 = WHOIS8Resolver()
        self._events: list[MultiZoneEvent] = []
        self._global_logger = NetLog8Client(source="multizone", endpoint="global-netlog")
        if clock is not None:
            self._global_logger._clock = clock

    @property
    def zones(self) -> dict[str, ZoneInstance]:
        return dict(self._zones)

    @property
    def zone_count(self) -> int:
        return len(self._zones)

    @property
    def events(self) -> list[MultiZoneEvent]:
        return list(self._events)

    @property
    def link_count(self) -> int:
        return len(self._links)

    def _record(self, zone: str, event: str, success: bool, detail: str = "") -> MultiZoneEvent:
        evt = MultiZoneEvent(zone=zone, event=event, success=success, detail=detail)
        self._events.append(evt)
        return evt

    def add_zone(self, definition: ZoneDefinition) -> ZoneInstance:
        """Create and register a new zone."""
        if definition.name in self._zones:
            raise ValueError(f"zone {definition.name!r} already exists")

        dfn = definition
        primary, secondary = make_zone_server_pair(dfn.zone_prefix)

        # OAuth8 keys
        primary.oauth8_cache.register_key(dfn.oauth8_key_id, dfn.oauth8_secret)
        secondary.oauth8_cache.register_key(dfn.oauth8_key_id, dfn.oauth8_secret)

        # Services
        for zs in (primary, secondary):
            zs.register_service(ZoneService(ZoneServiceType.DHCP8, f"dhcp.{dfn.zone_prefix}"))
            zs.register_service(ZoneService(ZoneServiceType.DNS8, f"dns.{dfn.zone_prefix}"))
            zs.register_service(ZoneService(ZoneServiceType.OAUTH8, f"oauth.{dfn.zone_prefix}"))
            zs.register_service(ZoneService(ZoneServiceType.NETLOG8, f"netlog.{dfn.zone_prefix}"))

        # ACL8: default deny, allow device→gateway
        primary.acl8_engine.add_rule(ACL8Rule(
            source="*", destination="gateway",
            action=ACL8Action.PERMIT,
            description="all devices to gateway",
        ))

        # DHCP8
        pool = DHCP8Pool(
            zone_prefix=dfn.zone_prefix_tuple,
            network_prefix=dfn.network_prefix,
        )
        services = DHCP8ServiceEndpoints(
            dns8=f"dns.{dfn.zone_prefix}",
            ntp8=f"ntp.{dfn.zone_prefix}",
            netlog8=f"netlog.{dfn.zone_prefix}",
            oauth8_cache=f"oauth.{dfn.zone_prefix}",
            zone_server_primary=f"{dfn.zone_prefix}.{dfn.network_prefix[0]}.{dfn.network_prefix[1]}.{dfn.network_prefix[2]}.254",
            zone_server_secondary=f"{dfn.zone_prefix}.{dfn.network_prefix[0]}.{dfn.network_prefix[1]}.{dfn.network_prefix[2]}.253",
        )
        dhcp_kwargs: dict[str, object] = {
            "pool": pool,
            "services": services,
            "lease_duration": dfn.lease_duration,
        }
        if self._clock is not None:
            dhcp_kwargs["_clock"] = self._clock
        dhcp_server = DHCP8Server(**dhcp_kwargs)  # type: ignore[arg-type]

        # Logger
        logger = NetLog8Client(source=f"zone-{dfn.name}", endpoint=f"netlog.{dfn.zone_prefix}")
        if self._clock is not None:
            logger._clock = self._clock

        # Routing — Tier 1 with own zone prefix
        prefix_str = f"{dfn.zone_prefix_tuple[0]}.{dfn.zone_prefix_tuple[1]}.{dfn.zone_prefix_tuple[2]}.{dfn.zone_prefix_tuple[3]}"
        tier1 = RouteTable(routes=[Route(
            destination_prefix=prefix_str,
            next_hop=f"{dfn.zone_prefix}.{dfn.network_prefix[0]}.{dfn.network_prefix[1]}.{dfn.network_prefix[2]}.254",
            interface="lo0",
        )])
        route_table = TwoTierRouteTable(tier1=tier1, tier2=RouteTable())

        instance = ZoneInstance(
            definition=dfn,
            primary=primary,
            secondary=secondary,
            dhcp_server=dhcp_server,
            logger=logger,
            route_table=route_table,
        )
        self._zones[dfn.name] = instance

        self._global_logger.info(
            NetLog8Facility.GENERAL,
            f"Zone {dfn.name} ({dfn.zone_prefix}) created",
        )
        self._record(dfn.name, "zone_created", True, dfn.zone_prefix)
        return instance

    def connect_zones(self, zone_a: str, zone_b: str) -> tuple[InterZoneLink, InterZoneLink]:
        """Create bidirectional inter-zone routing link (IBGP8-style)."""
        if zone_a not in self._zones:
            raise KeyError(f"zone {zone_a!r} not found")
        if zone_b not in self._zones:
            raise KeyError(f"zone {zone_b!r} not found")

        za = self._zones[zone_a]
        zb = self._zones[zone_b]

        # Add Tier 1 routes in both directions
        za_prefix = za.definition.zone_prefix_tuple
        zb_prefix = zb.definition.zone_prefix_tuple
        za_prefix_str = f"{za_prefix[0]}.{za_prefix[1]}.{za_prefix[2]}.{za_prefix[3]}"
        zb_prefix_str = f"{zb_prefix[0]}.{zb_prefix[1]}.{zb_prefix[2]}.{zb_prefix[3]}"

        np_b = zb.definition.network_prefix
        np_a = za.definition.network_prefix
        iface = f"ibgp8-{zone_a}-{zone_b}"

        za.route_table.tier1.add_route(Route(
            destination_prefix=zb_prefix_str,
            next_hop=f"{zb.definition.zone_prefix}.{np_b[0]}.{np_b[1]}.{np_b[2]}.254",
            interface=iface,
        ))
        zb.route_table.tier1.add_route(Route(
            destination_prefix=za_prefix_str,
            next_hop=f"{za.definition.zone_prefix}.{np_a[0]}.{np_a[1]}.{np_a[2]}.254",
            interface=iface,
        ))

        link_ab = InterZoneLink(zone_a, zone_b, iface)
        link_ba = InterZoneLink(zone_b, zone_a, iface)
        self._links.extend([link_ab, link_ba])

        self._global_logger.info(
            NetLog8Facility.ROUTING,
            f"Inter-zone link: {zone_a} ↔ {zone_b}",
        )
        self._record(zone_a, "inter_zone_link", True, f"{zone_a} ↔ {zone_b}")
        return link_ab, link_ba

    def provision_device(
        self, zone_name: str, client_id: str,
    ) -> DHCP8Lease | None:
        """Provision a device in a specific zone via DHCP8."""
        if zone_name not in self._zones:
            raise KeyError(f"zone {zone_name!r} not found")

        zone = self._zones[zone_name]
        lease = zone.dhcp_server.discover(client_id)
        if lease is None:
            zone.logger.warning(NetLog8Facility.DHCP8, f"Pool exhausted for {client_id}")
            self._record(zone_name, "provision", False, "pool exhausted")
            return None

        zone.logger.info(
            NetLog8Facility.DHCP8,
            f"Lease: {client_id} → {lease.address}",
        )
        self._record(zone_name, "provision", True, f"{client_id} → {lease.address}")
        return lease

    def authenticate_device(
        self, zone_name: str, client_id: str, now: float | None = None,
    ) -> bool:
        """Authenticate a device via OAuth8 in its zone."""
        if zone_name not in self._zones:
            raise KeyError(f"zone {zone_name!r} not found")

        zone = self._zones[zone_name]
        dfn = zone.definition
        try:
            token = zone.primary.oauth8_cache.issue_token(
                key_id=dfn.oauth8_key_id,
                subject=client_id,
                issuer=f"zoneserver.{dfn.zone_prefix}",
                audience=dfn.zone_prefix,
                duration=dfn.lease_duration,
                scopes=("network-access",),
                now=now,
            )
        except KeyError:
            self._record(zone_name, "authenticate", False, "key not found")
            return False

        result = zone.primary.authenticate_device(token, now=now)
        self._record(zone_name, "authenticate", result.is_valid, client_id)
        return result.is_valid

    def route_between_zones(
        self,
        src_zone: str,
        dst_zone: str,
        src_addr: IPv8Address,
        dst_addr: IPv8Address,
        payload: bytes = b"inter-zone",
    ) -> bool:
        """Route a packet from src_zone to dst_zone."""
        if src_zone not in self._zones:
            raise KeyError(f"zone {src_zone!r} not found")

        from ipv8lab.errors import NoRouteFoundError

        zone = self._zones[src_zone]
        pkt = IPv8Packet(src=src_addr, dst=dst_addr, payload=payload)
        pkt.to_bytes()

        try:
            route = zone.route_table.find_route(dst_addr)
        except NoRouteFoundError:
            zone.logger.warning(
                NetLog8Facility.ROUTING, f"No route to {dst_addr}",
            )
            self._record(src_zone, "inter_zone_route", False, f"no route to {dst_addr}")
            return False

        zone.logger.info(
            NetLog8Facility.ROUTING,
            f"Routed: {src_addr} → {dst_addr} via {route.next_hop}",
        )
        self._record(
            src_zone, "inter_zone_route", True,
            f"{src_addr} → {dst_addr} via {route.next_hop} ({route.interface})",
        )
        return True

    def authorize_cross_zone(
        self, zone_name: str, source: str, destination: str,
    ) -> bool:
        """Check ACL8 for cross-zone traffic via gateway."""
        if zone_name not in self._zones:
            raise KeyError(f"zone {zone_name!r} not found")

        zone = self._zones[zone_name]
        result = zone.primary.authorize_traffic(source, destination)
        self._record(
            zone_name, "acl8_cross_zone",
            result.is_permitted,
            f"{source} → {destination}: {'PERMIT' if result.is_permitted else 'DENY'}",
        )
        return result.is_permitted

    def get_zone(self, name: str) -> ZoneInstance:
        if name not in self._zones:
            raise KeyError(f"zone {name!r} not found")
        return self._zones[name]

    def list_zones(self) -> list[str]:
        return list(self._zones.keys())

    @property
    def all_events_passed(self) -> bool:
        return all(e.success for e in self._events)

    @property
    def failed_events(self) -> list[MultiZoneEvent]:
        return [e for e in self._events if not e.success]
