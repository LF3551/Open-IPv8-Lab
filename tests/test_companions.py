# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for companion spec modules."""

from ipv8lab.companions import (
    ARP8Entry,
    ARP8Table,
    BGP8Advertisement,
    BGP8Peer,
    BGP8State,
    BGP8Table,
    ISIS8Adjacency,
    ISIS8Level,
    NICCertification,
    NICCertLevel,
    OSPF8Area,
    OSPF8AreaType,
    OSPF8LSA,
    RINEFabric,
    RINEPeeringLink,
    SNMPv8MIB,
    SNMPv8OID,
    Update8Package,
    Update8Status,
    WiFi8AccessPoint,
    WiFi8Band,
    XLATE8Entry,
    XLATE8Table,
)


# ===================================================================
# BGP8
# ===================================================================

class TestBGP8:
    def test_peer_defaults(self):
        p = BGP8Peer(asn=64496, address="64496.192.0.2.1")
        assert p.state == BGP8State.IDLE
        assert p.is_ebgp is True

    def test_advertisement_valid_prefix(self):
        adv = BGP8Advertisement(
            prefix="64496.0.0.0.0/8", origin_asn=64496,
            prefix_length=8,
        )
        assert adv.is_valid_ebgp_prefix()

    def test_advertisement_invalid_prefix(self):
        adv = BGP8Advertisement(
            prefix="64496.192.168.0.0/24", origin_asn=64496,
            prefix_length=24,
        )
        assert not adv.is_valid_ebgp_prefix()

    def test_advertisement_boundary_16(self):
        adv = BGP8Advertisement(
            prefix="64496.192.0.0.0/16", origin_asn=64496,
            prefix_length=16,
        )
        assert adv.is_valid_ebgp_prefix()

    def test_table_install(self):
        t = BGP8Table()
        adv = BGP8Advertisement("64496/8", 64496, prefix_length=8)
        assert t.install(adv) is True
        assert t.size == 1

    def test_table_reject_specific_prefix(self):
        t = BGP8Table()
        adv = BGP8Advertisement("64496/24", 64496, prefix_length=24)
        assert t.install(adv) is False
        assert t.size == 0

    def test_table_withdraw(self):
        t = BGP8Table()
        t.install(BGP8Advertisement("64496/8", 64496, prefix_length=8))
        assert t.withdraw("64496/8") is True
        assert t.size == 0

    def test_table_withdraw_missing(self):
        t = BGP8Table()
        assert t.withdraw("nope") is False

    def test_table_lookup(self):
        t = BGP8Table()
        adv = BGP8Advertisement("64496/8", 64496, prefix_length=8, cf_accumulated=1.5)
        t.install(adv)
        found = t.lookup("64496/8")
        assert found is not None
        assert found.cf_accumulated == 1.5

    def test_table_best_path(self):
        t = BGP8Table()
        adv = BGP8Advertisement("64496/8", 64496, prefix_length=8)
        t.install(adv)
        assert t.best_path("64496/8") is adv

    def test_table_entries(self):
        t = BGP8Table()
        t.install(BGP8Advertisement("a/8", 1, prefix_length=8))
        t.install(BGP8Advertisement("b/8", 2, prefix_length=8))
        assert len(t.entries()) == 2

    def test_8to4_tunnel_endpoint(self):
        adv = BGP8Advertisement(
            "64496/8", 64496, prefix_length=8,
            tunnel_endpoint="198.51.100.1",
        )
        assert adv.tunnel_endpoint == "198.51.100.1"

    def test_all_states(self):
        names = {s.name for s in BGP8State}
        assert names == {"IDLE", "CONNECT", "ACTIVE", "OPEN_SENT", "OPEN_CONFIRM", "ESTABLISHED"}


# ===================================================================
# OSPF8
# ===================================================================

class TestOSPF8:
    def test_backbone_area(self):
        area = OSPF8Area(area_id=0)
        assert area.is_backbone

    def test_backbone_by_type(self):
        area = OSPF8Area(area_id=99, area_type=OSPF8AreaType.BACKBONE)
        assert area.is_backbone

    def test_non_backbone(self):
        area = OSPF8Area(area_id=1)
        assert not area.is_backbone

    def test_area_types(self):
        names = {t.name for t in OSPF8AreaType}
        assert names == {"NORMAL", "STUB", "NSSA", "BACKBONE"}

    def test_lsa(self):
        lsa = OSPF8LSA(
            lsa_type=1, link_state_id="10.0.0.1",
            advertising_router="r1", cf_export=2.5,
        )
        assert lsa.cf_export == 2.5
        assert lsa.sequence_number == 1


# ===================================================================
# IS-IS8
# ===================================================================

class TestISIS8:
    def test_adjacency(self):
        adj = ISIS8Adjacency(system_id="0000.0000.0001", level=ISIS8Level.L2)
        assert adj.level == ISIS8Level.L2
        assert adj.state == "Up"

    def test_levels(self):
        names = {lvl.name for lvl in ISIS8Level}
        assert names == {"L1", "L2", "L1_L2"}


# ===================================================================
# RINE
# ===================================================================

class TestRINE:
    def test_peering_link(self):
        link = RINEPeeringLink(
            local_asn=64496, remote_asn=64497,
            local_address="100.0.0.1", remote_address="100.0.0.2",
            ixp_name="IX-NYC",
        )
        assert link.is_valid_rine_address("100.0.0.1")
        assert not link.is_valid_rine_address("192.168.0.1")

    def test_fabric(self):
        fab = RINEFabric()
        fab.add_link(RINEPeeringLink(64496, 64497, "100.0.0.1", "100.0.0.2"))
        fab.add_link(RINEPeeringLink(64496, 64498, "100.0.0.3", "100.0.0.4"))
        fab.add_link(RINEPeeringLink(64497, 64498, "100.0.0.5", "100.0.0.6"))
        assert fab.link_count == 3
        peers = fab.find_peers(64496)
        assert len(peers) == 2

    def test_fabric_remove(self):
        fab = RINEFabric()
        fab.add_link(RINEPeeringLink(1, 2, "100.0.0.1", "100.0.0.2"))
        removed = fab.remove_link(0)
        assert removed.local_asn == 1
        assert fab.link_count == 0


# ===================================================================
# ARP8
# ===================================================================

class TestARP8:
    def test_entry_expiry(self):
        e = ARP8Entry("64496.10.0.0.1", "aa:bb:cc:dd:ee:ff", timestamp=100.0)
        assert not e.is_expired(100.0)
        assert e.is_expired(100.0 + 14400.0)

    def test_table_learn_lookup(self):
        t = ARP8Table()
        e = ARP8Entry("64496.10.0.0.1", "aa:bb:cc:dd:ee:ff")
        t.learn(e)
        assert t.lookup("64496.10.0.0.1") is e
        assert t.lookup("nope") is None
        assert t.size == 1

    def test_table_flush(self):
        t = ARP8Table()
        t.learn(ARP8Entry("a", "m1"))
        t.learn(ARP8Entry("b", "m2"))
        assert t.flush() == 2
        assert t.size == 0

    def test_table_flush_expired(self):
        t = ARP8Table()
        t.learn(ARP8Entry("a", "m1", timestamp=0.0))
        t.learn(ARP8Entry("b", "m2", timestamp=20000.0))
        removed = t.flush_expired(now=15000.0, ttl=14400.0)
        assert removed == 1
        assert t.size == 1

    def test_gratuitous_announce(self):
        t = ARP8Table()
        e = t.gratuitous_announce("64496.10.0.0.1", "aa:bb:cc:dd:ee:ff")
        assert e.is_gratuitous is True
        assert t.size == 1


# ===================================================================
# XLATE8
# ===================================================================

class TestXLATE8:
    def test_create_entry(self):
        t = XLATE8Table()
        e = XLATE8Entry("127.1.0.0.10.0.0.1", "64496.203.0.113.1",
                        internal_port=443, external_port=443)
        assert t.create_entry(e) is True
        assert t.size == 1

    def test_reject_no_dns(self):
        t = XLATE8Table()
        e = XLATE8Entry("127.1.0.0.10.0.0.1", "64496.203.0.113.1",
                        dns_validated=False, internal_port=80)
        assert t.create_entry(e) is False
        assert t.size == 0

    def test_lookup(self):
        t = XLATE8Table()
        e = XLATE8Entry("127.1.0.0.10.0.0.1", "64496.1.2.3",
                        internal_port=8080)
        t.create_entry(e)
        found = t.lookup_internal("127.1.0.0.10.0.0.1", 8080)
        assert found is not None
        assert found.external_address == "64496.1.2.3"

    def test_remove(self):
        t = XLATE8Table()
        t.create_entry(XLATE8Entry("a", "b", internal_port=1))
        assert t.remove("a", 1) is True
        assert t.size == 0

    def test_remove_missing(self):
        t = XLATE8Table()
        assert t.remove("x", 1) is False

    def test_entries(self):
        t = XLATE8Table()
        t.create_entry(XLATE8Entry("a", "b", internal_port=1))
        t.create_entry(XLATE8Entry("c", "d", internal_port=2))
        assert len(t.entries()) == 2


# ===================================================================
# Update8
# ===================================================================

class TestUpdate8:
    def test_dns_source(self):
        pkg = Update8Package(
            package_id="upd-1", vendor="ExampleNIC",
            version="2.0.0", source_dns="updates.example.com",
            component="nic-firmware",
        )
        assert pkg.is_dns_source()

    def test_ip_source_blocked(self):
        pkg = Update8Package(
            package_id="upd-2", vendor="ExampleNIC",
            version="2.0.0", source_dns="198.51.100.1",
            component="nic-firmware",
        )
        assert not pkg.is_dns_source()

    def test_statuses(self):
        names = {s.name for s in Update8Status}
        assert "AVAILABLE" in names
        assert "ROLLED_BACK" in names
        assert len(Update8Status) == 7


# ===================================================================
# NIC Certification
# ===================================================================

class TestNICCert:
    def test_levels(self):
        names = {lvl.name for lvl in NICCertLevel}
        assert names == {"UNCERTIFIED", "LEVEL_1", "LEVEL_2", "LEVEL_3"}

    def test_cert(self):
        cert = NICCertification(
            vendor="ExampleNIC", model="X1000",
            firmware_version="3.0.0",
            cert_level=NICCertLevel.LEVEL_3,
            rate_limit_enforced=True,
            acl8_enforced=True,
            rollback_prevention=True,
        )
        assert cert.cert_level == NICCertLevel.LEVEL_3
        assert cert.rollback_prevention


# ===================================================================
# WiFi8
# ===================================================================

class TestWiFi8:
    def test_ap(self):
        ap = WiFi8AccessPoint(
            ssid="Corp-WiFi8", bssid="aa:bb:cc:dd:ee:ff",
            band=WiFi8Band.BAND_6GHZ,
            zone_server_address="127.1.0.0.192.168.1.254",
            oauth8_required=True,
            vlan_id=100,
        )
        assert ap.band == WiFi8Band.BAND_6GHZ
        assert ap.oauth8_required

    def test_bands(self):
        names = {b.name for b in WiFi8Band}
        assert names == {"BAND_2_4GHZ", "BAND_5GHZ", "BAND_6GHZ"}


# ===================================================================
# SNMPv8 MIB
# ===================================================================

class TestSNMPv8:
    def test_register_get(self):
        mib = SNMPv8MIB()
        oid = SNMPv8OID("1.3.6.1.4.1.99999.1", "ipv8RoutingTableSize")
        mib.register(oid)
        assert mib.get("1.3.6.1.4.1.99999.1") is oid
        assert mib.get("nope") is None

    def test_walk(self):
        mib = SNMPv8MIB()
        mib.register(SNMPv8OID("1.3.6.1.4.1.99999.1", "a"))
        mib.register(SNMPv8OID("1.3.6.1.4.1.99999.2", "b"))
        mib.register(SNMPv8OID("1.3.6.1.4.1.88888.1", "c"))
        results = mib.walk("1.3.6.1.4.1.99999")
        assert len(results) == 2

    def test_walk_all(self):
        mib = SNMPv8MIB()
        mib.register(SNMPv8OID("1.1", "a"))
        mib.register(SNMPv8OID("2.1", "b"))
        assert len(mib.walk()) == 2

    def test_size(self):
        mib = SNMPv8MIB()
        assert mib.size == 0
        mib.register(SNMPv8OID("1.1", "a"))
        assert mib.size == 1
