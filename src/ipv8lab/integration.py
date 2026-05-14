# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""End-to-end integration scenario: DHCP8 → OAuth8 → ACL8 → routing.

Models the complete device onboarding lifecycle in an IPv8 network:

1. Zone Server pair is created for a zone (primary .254, secondary .253)
2. DHCP8 server provisions device with address + all service endpoints
3. OAuth8 cache issues JWT token for the device
4. ACL8 engine authorises device traffic (east-west enforcement)
5. WHOIS8 validates the route (north-south egress)
6. Packet is built and routed through two-tier routing table
7. Ingress filter validates the packet at border
8. NetLog8 records telemetry for every step

This module ties together: dhcp8, zoneserver, whois8, route, packet,
security, netlog8, address.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ipv8lab.address import IPv8Address
from ipv8lab.dhcp8 import DHCP8Pool, DHCP8Server, DHCP8ServiceEndpoints
from ipv8lab.netlog8 import NetLog8Client, NetLog8Facility
from ipv8lab.packet import IPv8Packet
from ipv8lab.route import Route, RouteTable, TwoTierRouteTable
from ipv8lab.security import IngressFilter
from ipv8lab.whois8 import WHOIS8Record, WHOIS8Resolver
from ipv8lab.zoneserver import (
    ACL8Action,
    ACL8Rule,
    ZoneServer,
    ZoneService,
    ZoneServiceType,
    make_zone_server_pair,
)


# ---------------------------------------------------------------------------
# Step results
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class StepResult:
    """Result of a single integration step."""

    step: str
    success: bool
    detail: str = ""


@dataclass
class IntegrationResult:
    """Accumulated result of end-to-end scenario."""

    steps: list[StepResult] = field(default_factory=list)

    @property
    def all_passed(self) -> bool:
        return all(s.success for s in self.steps)

    @property
    def failed_steps(self) -> list[StepResult]:
        return [s for s in self.steps if not s.success]

    def add(self, step: str, success: bool, detail: str = "") -> StepResult:
        r = StepResult(step=step, success=success, detail=detail)
        self.steps.append(r)
        return r


# ---------------------------------------------------------------------------
# Zone configuration
# ---------------------------------------------------------------------------

@dataclass
class ZoneConfig:
    """Configuration for an IPv8 zone used in integration scenarios."""

    zone_prefix: str = "127.1.0.0"
    asn: int = 64496
    network_prefix: tuple[int, int, int] = (192, 0, 2)
    gateway_interface: str = "ge-0/0/0"
    oauth8_key_id: str = "zone-key-1"
    oauth8_secret: bytes = b"integration-test-secret"
    lease_duration: int = 3600
    whois8_holder: str = "Example-Corp"
    whois8_country: str = "US"


# ---------------------------------------------------------------------------
# Integration scenario
# ---------------------------------------------------------------------------

class EndToEndScenario:
    """Full device onboarding scenario.

    DHCP8 → OAuth8 → ACL8 → WHOIS8 → Routing → Ingress → NetLog8
    """

    def __init__(self, config: ZoneConfig | None = None, clock: object | None = None) -> None:
        self.config = config or ZoneConfig()
        self._clock = clock
        self._result = IntegrationResult()
        self._logger = NetLog8Client(source="integration", endpoint="netlog.zone")
        if clock is not None:
            self._logger._clock = clock

        # Will be initialised during run
        self._primary: ZoneServer | None = None
        self._secondary: ZoneServer | None = None
        self._dhcp_server: DHCP8Server | None = None
        self._whois8: WHOIS8Resolver | None = None
        self._route_table: TwoTierRouteTable | None = None
        self._ingress: IngressFilter | None = None

    @property
    def result(self) -> IntegrationResult:
        return self._result

    @property
    def logger(self) -> NetLog8Client:
        return self._logger

    def setup_zone(self) -> StepResult:
        """Step 1: Create Zone Server pair and register services."""
        cfg = self.config
        self._primary, self._secondary = make_zone_server_pair(cfg.zone_prefix)

        # Register OAuth8 key
        self._primary.oauth8_cache.register_key(cfg.oauth8_key_id, cfg.oauth8_secret)
        self._secondary.oauth8_cache.register_key(cfg.oauth8_key_id, cfg.oauth8_secret)

        # Register services
        for zs in (self._primary, self._secondary):
            zs.register_service(ZoneService(ZoneServiceType.DHCP8, f"dhcp.{cfg.zone_prefix}"))
            zs.register_service(ZoneService(ZoneServiceType.DNS8, f"dns.{cfg.zone_prefix}"))
            zs.register_service(ZoneService(ZoneServiceType.OAUTH8, f"oauth.{cfg.zone_prefix}"))
            zs.register_service(ZoneService(ZoneServiceType.NETLOG8, f"netlog.{cfg.zone_prefix}"))

        # Setup DHCP8
        from ipv8lab.address import asn_to_prefix, asn_to_prefix_str
        zone_prefix_tuple = asn_to_prefix(cfg.asn)
        pool = DHCP8Pool(
            zone_prefix=zone_prefix_tuple,
            network_prefix=cfg.network_prefix,
        )
        services = DHCP8ServiceEndpoints(
            dns8=f"dns.{cfg.zone_prefix}",
            ntp8=f"ntp.{cfg.zone_prefix}",
            netlog8=f"netlog.{cfg.zone_prefix}",
            oauth8_cache=f"oauth.{cfg.zone_prefix}",
            zone_server_primary=f"{cfg.zone_prefix}.{cfg.network_prefix[0]}.{cfg.network_prefix[1]}.{cfg.network_prefix[2]}.254",
            zone_server_secondary=f"{cfg.zone_prefix}.{cfg.network_prefix[0]}.{cfg.network_prefix[1]}.{cfg.network_prefix[2]}.253",
        )
        kwargs: dict[str, object] = {
            "pool": pool,
            "services": services,
            "lease_duration": cfg.lease_duration,
        }
        if self._clock is not None:
            kwargs["_clock"] = self._clock
        self._dhcp_server = DHCP8Server(**kwargs)  # type: ignore[arg-type]

        # Setup WHOIS8
        self._whois8 = WHOIS8Resolver()
        self._whois8.register(WHOIS8Record(
            asn=cfg.asn, holder=cfg.whois8_holder, country=cfg.whois8_country,
        ))

        # Setup routing
        gw_addr = IPv8Address.parse(f"{cfg.asn}.{cfg.network_prefix[0]}.{cfg.network_prefix[1]}.{cfg.network_prefix[2]}.254")
        tier1 = RouteTable(routes=[Route(
            destination_prefix=asn_to_prefix_str(cfg.asn),
            next_hop=str(gw_addr),
            interface=cfg.gateway_interface,
        )])
        self._route_table = TwoTierRouteTable(tier1=tier1, tier2=RouteTable())

        # Setup ingress filter
        self._ingress = IngressFilter(peer_asn=cfg.asn)

        self._logger.info(
            NetLog8Facility.GENERAL, "Zone setup complete",
            metadata={"zone": cfg.zone_prefix, "asn": cfg.asn},
        )
        return self._result.add("zone_setup", True, f"Zone {cfg.zone_prefix} with ASN {cfg.asn}")

    def provision_device(self, client_id: str) -> StepResult:
        """Step 2: DHCP8 lease provisioning."""
        if self._dhcp_server is None:
            return self._result.add("dhcp8_provision", False, "zone not setup")

        lease = self._dhcp_server.discover(client_id)
        if lease is None:
            self._logger.warning(NetLog8Facility.DHCP8, f"DHCP8 pool exhausted for {client_id}")
            return self._result.add("dhcp8_provision", False, "pool exhausted")

        self._logger.info(
            NetLog8Facility.DHCP8, f"Lease granted to {client_id}",
            metadata={
                "address": str(lease.address),
                "gateway_even": str(lease.gateway_even),
                "gateway_odd": str(lease.gateway_odd),
                "services": {
                    "dns8": lease.services.dns8,
                    "ntp8": lease.services.ntp8,
                    "netlog8": lease.services.netlog8,
                    "oauth8": lease.services.oauth8_cache,
                },
            },
        )
        return self._result.add(
            "dhcp8_provision", True,
            f"{client_id} → {lease.address}",
        )

    def authenticate_device(self, client_id: str, now: float | None = None) -> StepResult:
        """Step 3: OAuth8 token issuance and validation."""
        if self._primary is None:
            return self._result.add("oauth8_auth", False, "zone not setup")

        cfg = self.config
        try:
            token_raw = self._primary.oauth8_cache.issue_token(
                key_id=cfg.oauth8_key_id,
                subject=client_id,
                issuer=f"zoneserver.{cfg.zone_prefix}",
                audience=cfg.zone_prefix,
                duration=cfg.lease_duration,
                scopes=("network-access",),
                now=now,
            )
        except KeyError as exc:
            return self._result.add("oauth8_auth", False, str(exc))

        result = self._primary.authenticate_device(token_raw, now=now)
        if not result.is_valid:
            self._logger.sec_alert(
                NetLog8Facility.OAUTH8,
                f"Auth failed for {client_id}: {result.reason}",
            )
            return self._result.add("oauth8_auth", False, result.reason)

        self._logger.info(
            NetLog8Facility.OAUTH8, f"Device {client_id} authenticated",
            metadata={"subject": client_id, "scopes": ["network-access"]},
        )
        return self._result.add("oauth8_auth", True, f"{client_id} authenticated")

    def authorize_traffic(
        self, source: str, destination: str,
    ) -> StepResult:
        """Step 4: ACL8 east-west traffic authorisation."""
        if self._primary is None:
            return self._result.add("acl8_authorize", False, "zone not setup")

        acl_result = self._primary.authorize_traffic(source, destination)
        if not acl_result.is_permitted:
            self._logger.sec_alert(
                NetLog8Facility.ACL8,
                f"Traffic denied: {source} → {destination}: {acl_result.reason}",
            )
            return self._result.add(
                "acl8_authorize", False,
                f"DENIED {source} → {destination}: {acl_result.reason}",
            )

        self._logger.info(
            NetLog8Facility.ACL8,
            f"Traffic permitted: {source} → {destination}",
        )
        return self._result.add(
            "acl8_authorize", True,
            f"PERMIT {source} → {destination}",
        )

    def validate_egress(self, destination: IPv8Address) -> StepResult:
        """Step 5: WHOIS8 north-south egress validation."""
        if self._whois8 is None:
            return self._result.add("whois8_validate", False, "zone not setup")

        result = self._whois8.validate_destination(destination)
        if not result.is_valid:
            self._logger.sec_alert(
                NetLog8Facility.WHOIS8,
                f"Egress denied for {destination}: {result.reason}",
                metadata={"status": result.status.name},
            )
            return self._result.add(
                "whois8_validate", False,
                f"DENIED {destination}: {result.reason}",
            )

        self._logger.info(
            NetLog8Facility.WHOIS8,
            f"Egress validated for {destination}",
        )
        return self._result.add("whois8_validate", True, f"VALID {destination}")

    def route_packet(self, src: IPv8Address, dst: IPv8Address, payload: bytes = b"hello") -> StepResult:
        """Step 6: Build packet and route through two-tier table."""
        if self._route_table is None:
            return self._result.add("routing", False, "zone not setup")

        from ipv8lab.errors import NoRouteFoundError

        pkt = IPv8Packet(src=src, dst=dst, payload=payload)
        pkt_bytes = pkt.to_bytes()

        try:
            route = self._route_table.find_route(dst)
        except NoRouteFoundError:
            self._logger.warning(
                NetLog8Facility.ROUTING,
                f"No route to {dst}",
            )
            return self._result.add("routing", False, f"no route to {dst}")

        self._logger.info(
            NetLog8Facility.ROUTING,
            f"Packet routed: {src} → {dst} via {route.next_hop} ({route.interface})",
            metadata={"packet_size": len(pkt_bytes)},
        )
        return self._result.add(
            "routing", True,
            f"{src} → {dst} via {route.next_hop}",
        )

    def check_ingress(self, src: IPv8Address, dst: IPv8Address, payload: bytes = b"hello") -> StepResult:
        """Step 7: Ingress filter validation at border."""
        if self._ingress is None:
            return self._result.add("ingress_filter", False, "zone not setup")

        pkt = IPv8Packet(src=src, dst=dst, payload=payload)
        violations = self._ingress.check(pkt)
        if violations:
            for violation in violations:
                self._logger.sec_alert(
                    NetLog8Facility.SECURITY,
                    violation.message,
                    metadata={"section": violation.section},
                )
            reasons = "; ".join(v.message for v in violations)
            return self._result.add("ingress_filter", False, reasons)

        self._logger.info(NetLog8Facility.SECURITY, "Ingress filter passed")
        return self._result.add("ingress_filter", True, "clean")

    def run_full_scenario(
        self,
        client_id: str = "device-1",
        destination_asn: int | None = None,
        now: float | None = None,
    ) -> IntegrationResult:
        """Run the complete DHCP8 → OAuth8 → ACL8 → routing scenario.

        Returns IntegrationResult with all step outcomes.
        """
        cfg = self.config
        dest_asn = destination_asn if destination_asn is not None else cfg.asn

        # Register destination ASN in WHOIS8 if different
        if self._whois8 is not None and dest_asn != cfg.asn:
            try:
                self._whois8.register(WHOIS8Record(
                    asn=dest_asn, holder="Remote-AS", country="XX",
                ))
            except ValueError:
                pass  # reserved ASN — will fail at validation

        # 1. Zone setup
        self.setup_zone()

        # Re-register extra ASN after setup (setup creates fresh resolver)
        if dest_asn != cfg.asn:
            try:
                self._whois8.register(WHOIS8Record(  # type: ignore[union-attr]
                    asn=dest_asn, holder="Remote-AS", country="XX",
                ))
            except ValueError:
                pass
            # Add Tier 1 route for destination ASN
            if self._route_table is not None:
                from ipv8lab.address import asn_to_prefix_str
                self._route_table.tier1.add_route(Route(
                    destination_prefix=asn_to_prefix_str(dest_asn),
                    next_hop="border-router",
                    interface="ge-0/0/1",
                ))

        # 2. DHCP8 provision
        self.provision_device(client_id)

        # 3. OAuth8 auth
        self.authenticate_device(client_id, now=now)

        # 4. ACL8 — add permit rule for device→gateway, then check
        if self._primary is not None:
            self._primary.acl8_engine.add_rule(ACL8Rule(
                source=client_id,
                destination="gateway",
                action=ACL8Action.PERMIT,
                description="device to gateway",
            ))
        self.authorize_traffic(client_id, "gateway")

        # 5. Build addresses
        lease = self._dhcp_server.get_lease(client_id) if self._dhcp_server else None
        if lease is None:
            return self._result

        src_addr = lease.address
        np = cfg.network_prefix
        dst_addr = IPv8Address.parse(f"{dest_asn}.{np[0]}.{np[1]}.{np[2]}.100")

        # 5. WHOIS8 egress validation
        self.validate_egress(dst_addr)

        # 6. Route packet
        self.route_packet(src_addr, dst_addr)

        # 7. Ingress filter
        self.check_ingress(src_addr, dst_addr)

        return self._result
