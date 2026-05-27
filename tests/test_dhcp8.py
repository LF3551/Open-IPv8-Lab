# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for DHCP8 lease simulation."""

import pytest

from ipv8lab.dhcp8 import (
    DHCP8Lease,
    DHCP8MessageType,
    DHCP8Pool,
    DHCP8Server,
    DHCP8ServiceEndpoints,
)
from ipv8lab.interface_mode import (
    DHCP8_OPT_IFACE_MODE,
    DHCP8_OPT_PRIMARY_RN,
    InterfaceMode,
)


# ---------------------------------------------------------------------------
# MessageType
# ---------------------------------------------------------------------------

class TestDHCP8MessageType:
    def test_all_types(self):
        names = {m.name for m in DHCP8MessageType}
        assert names == {"DISCOVER", "OFFER", "REQUEST", "ACK", "NAK", "RELEASE"}


# ---------------------------------------------------------------------------
# ServiceEndpoints
# ---------------------------------------------------------------------------

class TestDHCP8ServiceEndpoints:
    def test_defaults(self):
        ep = DHCP8ServiceEndpoints()
        assert ep.dns8 == ""
        assert ep.ntp8 == ""
        assert ep.netlog8 == ""
        assert ep.oauth8_cache == ""

    def test_custom(self):
        ep = DHCP8ServiceEndpoints(dns8="8.8.8.8", ntp8="ntp.example")
        assert ep.dns8 == "8.8.8.8"
        assert ep.ntp8 == "ntp.example"


# ---------------------------------------------------------------------------
# Pool
# ---------------------------------------------------------------------------

class TestDHCP8Pool:
    @pytest.fixture()
    def pool(self) -> DHCP8Pool:
        return DHCP8Pool(
            zone_prefix=(0, 0, 251, 240),
            network_prefix=(192, 0, 2),
        )

    def test_available(self, pool: DHCP8Pool):
        assert pool.available == 240  # 10..249

    def test_allocate(self, pool: DHCP8Pool):
        addr = pool.allocate()
        assert addr is not None
        assert str(addr).endswith(".10")
        addr2 = pool.allocate()
        assert addr2 is not None
        assert str(addr2).endswith(".11")
        assert pool.available == 238

    def test_allocate_exhausted(self):
        pool = DHCP8Pool(
            zone_prefix=(0, 0, 251, 240),
            network_prefix=(10, 0, 0),
            start=249,
            end=249,
        )
        a = pool.allocate()
        assert a is not None
        assert pool.allocate() is None
        assert pool.available == 0

    def test_reset(self, pool: DHCP8Pool):
        pool.allocate()
        pool.allocate()
        pool.reset()
        assert pool.available == 240


# ---------------------------------------------------------------------------
# Lease
# ---------------------------------------------------------------------------

class TestDHCP8Lease:
    def test_expires_at(self):
        from ipv8lab.address import IPv8Address

        addr = IPv8Address.parse("64496-192.0.2.10")
        gw_e = IPv8Address.parse("64496-192.0.2.254")
        gw_o = IPv8Address.parse("64496-192.0.2.253")
        lease = DHCP8Lease(
            address=addr,
            gateway_even=gw_e,
            gateway_odd=gw_o,
            lease_duration=3600,
            issued_at=1000.0,
        )
        assert lease.expires_at == 4600.0
        assert not lease.is_expired(1000.0)
        assert lease.is_expired(4600.0)

    def test_mgmt_oob_defaults(self):
        from ipv8lab.address import IPv8Address

        addr = IPv8Address.parse("64496-192.0.2.10")
        gw = IPv8Address.parse("64496-192.0.2.254")
        lease = DHCP8Lease(address=addr, gateway_even=gw, gateway_odd=gw)
        assert lease.mgmt_vlan == 4090
        assert lease.oob_vlan == 4091


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

class TestDHCP8Server:
    @pytest.fixture()
    def server(self) -> DHCP8Server:
        pool = DHCP8Pool(
            zone_prefix=(0, 0, 251, 240),
            network_prefix=(192, 0, 2),
        )
        services = DHCP8ServiceEndpoints(
            dns8="dns.zone.example",
            ntp8="ntp.zone.example",
            netlog8="netlog.zone.example",
            oauth8_cache="oauth.zone.example",
            zone_server_primary="zs.254",
            zone_server_secondary="zs.253",
        )
        clock = _FakeClock(0.0)
        return DHCP8Server(
            pool=pool,
            services=services,
            lease_duration=3600,
            _clock=clock,
        )

    def test_discover_assigns_address(self, server: DHCP8Server):
        lease = server.discover("client-1")
        assert lease is not None
        assert str(lease.address).endswith(".10")
        assert server.active_leases == 1

    def test_discover_returns_same_lease(self, server: DHCP8Server):
        l1 = server.discover("client-1")
        l2 = server.discover("client-1")
        assert l1 is l2
        assert server.active_leases == 1

    def test_discover_multiple_clients(self, server: DHCP8Server):
        l1 = server.discover("c1")
        l2 = server.discover("c2")
        assert l1 is not None and l2 is not None
        assert l1.address != l2.address
        assert server.active_leases == 2

    def test_gateways_even_odd(self, server: DHCP8Server):
        lease = server.discover("c1")
        assert lease is not None
        assert str(lease.gateway_even).endswith(".254")
        assert str(lease.gateway_odd).endswith(".253")

    def test_services_delivered(self, server: DHCP8Server):
        lease = server.discover("c1")
        assert lease is not None
        assert lease.services.dns8 == "dns.zone.example"
        assert lease.services.ntp8 == "ntp.zone.example"
        assert lease.services.netlog8 == "netlog.zone.example"
        assert lease.services.oauth8_cache == "oauth.zone.example"
        assert lease.services.zone_server_primary == "zs.254"
        assert lease.services.zone_server_secondary == "zs.253"

    def test_release(self, server: DHCP8Server):
        server.discover("c1")
        assert server.release("c1") is True
        assert server.active_leases == 0
        assert server.get_lease("c1") is None

    def test_release_unknown(self, server: DHCP8Server):
        assert server.release("unknown") is False

    def test_get_lease(self, server: DHCP8Server):
        server.discover("c1")
        lease = server.get_lease("c1")
        assert lease is not None
        assert str(lease.address).endswith(".10")

    def test_expired_lease_reassigns(self, server: DHCP8Server):
        clock: _FakeClock = server._clock  # type: ignore[assignment]
        l1 = server.discover("c1")
        assert l1 is not None
        clock.now = 4000.0  # > 3600
        l2 = server.discover("c1")
        assert l2 is not None
        assert l2 is not l1  # new lease

    def test_pool_exhaustion(self):
        pool = DHCP8Pool(
            zone_prefix=(0, 0, 251, 240),
            network_prefix=(10, 0, 0),
            start=249,
            end=249,
        )
        server = DHCP8Server(pool=pool, _clock=_FakeClock(0.0))
        assert server.discover("c1") is not None
        assert server.discover("c2") is None

    def test_lease_duration(self, server: DHCP8Server):
        lease = server.discover("c1")
        assert lease is not None
        assert lease.lease_duration == 3600
        assert lease.issued_at == 0.0
        assert lease.expires_at == 3600.0

    def test_lease_not_expired_just_before(self, server: DHCP8Server):
        lease = server.discover("c1")
        assert lease is not None
        assert not lease.is_expired(3599.99)

    def test_lease_expired_exactly(self, server: DHCP8Server):
        lease = server.discover("c1")
        assert lease is not None
        assert lease.is_expired(3600.0)


class _FakeClock:
    def __init__(self, now: float) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


# ---------------------------------------------------------------------------
# InterfaceMode (spec §7.7.1)
# ---------------------------------------------------------------------------

class TestInterfaceMode:
    def test_all_values(self):
        assert InterfaceMode.NORMAL == 0
        assert InterfaceMode.STRICT == 1
        assert InterfaceMode.PNP == 2
        assert InterfaceMode.GUEST == 3

    def test_printer_alias_is_pnp(self):
        assert InterfaceMode.PRINTER == InterfaceMode.PNP  # type: ignore[attr-defined]

    def test_to_wire(self):
        assert InterfaceMode.NORMAL.to_wire() == 0
        assert InterfaceMode.STRICT.to_wire() == 1
        assert InterfaceMode.PNP.to_wire() == 2
        assert InterfaceMode.GUEST.to_wire() == 3

    def test_from_wire(self):
        assert InterfaceMode.from_wire(0) is InterfaceMode.NORMAL
        assert InterfaceMode.from_wire(1) is InterfaceMode.STRICT
        assert InterfaceMode.from_wire(2) is InterfaceMode.PNP
        assert InterfaceMode.from_wire(3) is InterfaceMode.GUEST

    def test_from_wire_unknown(self):
        import pytest
        with pytest.raises(ValueError, match="Unknown InterfaceMode"):
            InterfaceMode.from_wire(99)

    def test_roundtrip(self):
        for mode in (InterfaceMode.NORMAL, InterfaceMode.STRICT,
                     InterfaceMode.PNP, InterfaceMode.GUEST):
            assert InterfaceMode.from_wire(mode.to_wire()) is mode

    def test_opt_constants(self):
        assert DHCP8_OPT_PRIMARY_RN == 222
        assert DHCP8_OPT_IFACE_MODE == 223


# ---------------------------------------------------------------------------
# DHCP8 options 222 / 223 in lease and server
# ---------------------------------------------------------------------------

class TestDHCP8LeaseOptions:
    def _make_lease(self, primary_rn=0, mode=InterfaceMode.NORMAL):
        from ipv8lab.address import IPv8Address
        addr = IPv8Address.parse("64496-192.0.2.10")
        gw = IPv8Address.parse("64496-192.0.2.254")
        return DHCP8Lease(
            address=addr, gateway_even=gw, gateway_odd=gw,
            primary_rn=primary_rn, interface_mode=mode,
        )

    def test_default_primary_rn(self):
        lease = self._make_lease()
        assert lease.primary_rn == 0

    def test_default_interface_mode(self):
        lease = self._make_lease()
        assert lease.interface_mode is InterfaceMode.NORMAL

    def test_custom_primary_rn(self):
        lease = self._make_lease(primary_rn=64496)
        assert lease.primary_rn == 64496

    def test_custom_interface_mode_strict(self):
        lease = self._make_lease(mode=InterfaceMode.STRICT)
        assert lease.interface_mode is InterfaceMode.STRICT

    def test_custom_interface_mode_pnp(self):
        lease = self._make_lease(mode=InterfaceMode.PNP)
        assert lease.interface_mode is InterfaceMode.PNP

    def test_custom_interface_mode_guest(self):
        lease = self._make_lease(mode=InterfaceMode.GUEST)
        assert lease.interface_mode is InterfaceMode.GUEST


class TestDHCP8ServerOptions:
    def _make_server(self, primary_rn=64496, mode=InterfaceMode.STRICT):
        pool = DHCP8Pool(
            zone_prefix=(0, 0, 251, 240),
            network_prefix=(192, 0, 2),
        )
        return DHCP8Server(
            pool=pool,
            primary_rn=primary_rn,
            interface_mode=mode,
            _clock=_FakeClock(0.0),
        )

    def test_server_delivers_primary_rn(self):
        server = self._make_server(primary_rn=64496)
        lease = server.discover("c1")
        assert lease is not None
        assert lease.primary_rn == 64496

    def test_server_delivers_interface_mode(self):
        server = self._make_server(mode=InterfaceMode.STRICT)
        lease = server.discover("c1")
        assert lease is not None
        assert lease.interface_mode is InterfaceMode.STRICT

    def test_server_delivers_guest_mode(self):
        server = self._make_server(mode=InterfaceMode.GUEST)
        lease = server.discover("c1")
        assert lease is not None
        assert lease.interface_mode is InterfaceMode.GUEST

    def test_server_default_mode_is_normal(self):
        pool = DHCP8Pool(
            zone_prefix=(0, 0, 251, 240),
            network_prefix=(10, 0, 0),
        )
        server = DHCP8Server(pool=pool, _clock=_FakeClock(0.0))
        lease = server.discover("c1")
        assert lease is not None
        assert lease.interface_mode is InterfaceMode.NORMAL
        assert lease.primary_rn == 0

    def test_renewed_lease_retains_options(self):
        server = self._make_server(primary_rn=64496, mode=InterfaceMode.PNP)
        l1 = server.discover("c1")
        l2 = server.discover("c1")
        assert l1 is l2  # same lease, not expired
        assert l2 is not None
        assert l2.primary_rn == 64496
        assert l2.interface_mode is InterfaceMode.PNP
