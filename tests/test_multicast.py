# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for multicast/broadcast per Sections 10-12."""

from ipv8lab.address import IPv8Address
from ipv8lab.multicast import (
    MulticastType,
    analyze_multicast,
    classify_multicast,
    is_deprecated_protocol,
    multicast_group_name,
)


class TestClassifyMulticast:
    def test_intra_asn_multicast(self):
        addr = IPv8Address.parse("0.0.0.0.224.0.0.1")
        assert classify_multicast(addr) == MulticastType.INTRA_ASN

    def test_intra_asn_admin_scoped(self):
        addr = IPv8Address.parse("0.0.0.0.239.0.0.1")
        assert classify_multicast(addr) == MulticastType.INTRA_ASN

    def test_cross_asn_general(self):
        addr = IPv8Address.parse("255.255.0.0.224.0.0.1")
        assert classify_multicast(addr) == MulticastType.CROSS_ASN_GENERAL

    def test_ospf8_protocol(self):
        addr = IPv8Address.parse("255.255.0.1.224.0.0.5")
        assert classify_multicast(addr) == MulticastType.OSPF8

    def test_bgp8_protocol(self):
        addr = IPv8Address.parse("255.255.0.2.224.0.0.1")
        assert classify_multicast(addr) == MulticastType.BGP8

    def test_eigrp_deprecated(self):
        addr = IPv8Address.parse("255.255.0.3.0.0.0.0")
        assert classify_multicast(addr) == MulticastType.EIGRP_DEPRECATED

    def test_rip_deprecated(self):
        addr = IPv8Address.parse("255.255.0.4.0.0.0.0")
        assert classify_multicast(addr) == MulticastType.RIP_DEPRECATED

    def test_isis8(self):
        addr = IPv8Address.parse("255.255.0.5.0.0.0.0")
        assert classify_multicast(addr) == MulticastType.ISIS8

    def test_unknown_cross_asn(self):
        addr = IPv8Address.parse("255.255.0.99.0.0.0.0")
        assert classify_multicast(addr) == MulticastType.UNKNOWN_PROTOCOL

    def test_not_multicast(self):
        addr = IPv8Address.parse("64496-192.0.2.1")
        assert classify_multicast(addr) == MulticastType.NOT_MULTICAST


class TestMulticastGroupName:
    def test_all_routers(self):
        addr = IPv8Address.parse("255.255.0.0.224.0.0.1")
        assert multicast_group_name(addr) == "All IPv8 routers"

    def test_all_zone_servers(self):
        addr = IPv8Address.parse("255.255.0.0.224.0.0.2")
        assert multicast_group_name(addr) == "All IPv8 Zone Servers"

    def test_ospf8_all_routers(self):
        addr = IPv8Address.parse("255.255.0.1.224.0.0.5")
        assert multicast_group_name(addr) == "OSPF8 all routers"

    def test_ospf8_designated(self):
        addr = IPv8Address.parse("255.255.0.0.224.0.0.6")
        assert multicast_group_name(addr) == "OSPF8 designated routers"

    def test_ibgp8_discovery(self):
        addr = IPv8Address.parse("255.255.0.2.224.0.0.10")
        assert multicast_group_name(addr) == "IBGP8 peer discovery"

    def test_unknown_group(self):
        addr = IPv8Address.parse("255.255.0.0.224.0.0.99")
        assert multicast_group_name(addr) is None


class TestDeprecatedProtocol:
    def test_eigrp_is_deprecated(self):
        addr = IPv8Address.parse("255.255.0.3.0.0.0.0")
        assert is_deprecated_protocol(addr)

    def test_rip_is_deprecated(self):
        addr = IPv8Address.parse("255.255.0.4.0.0.0.0")
        assert is_deprecated_protocol(addr)

    def test_ospf8_not_deprecated(self):
        addr = IPv8Address.parse("255.255.0.1.224.0.0.5")
        assert not is_deprecated_protocol(addr)


class TestAnalyzeMulticast:
    def test_intra_asn_not_routable_beyond_as(self):
        addr = IPv8Address.parse("0.0.0.0.224.0.0.1")
        info = analyze_multicast(addr)
        assert info.multicast_type == MulticastType.INTRA_ASN
        assert info.routable_beyond_as is False
        assert info.group_name == "All IPv8 routers"

    def test_cross_asn_routable(self):
        addr = IPv8Address.parse("255.255.0.0.224.0.0.1")
        info = analyze_multicast(addr)
        assert info.routable_beyond_as is True
        assert info.deprecated is False

    def test_deprecated_flagged(self):
        addr = IPv8Address.parse("255.255.0.3.0.0.0.0")
        info = analyze_multicast(addr)
        assert info.deprecated is True

    def test_unicast_not_multicast(self):
        addr = IPv8Address.parse("64496-192.0.2.1")
        info = analyze_multicast(addr)
        assert info.multicast_type == MulticastType.NOT_MULTICAST
        assert info.routable_beyond_as is False


class TestBroadcast:
    def test_broadcast_is_not_multicast(self):
        addr = IPv8Address.parse("255.255.255.255.255.255.255.255")
        assert classify_multicast(addr) == MulticastType.NOT_MULTICAST

    def test_broadcast_not_routable(self):
        addr = IPv8Address.parse("255.255.255.255.255.255.255.255")
        assert addr.is_broadcast()
        info = analyze_multicast(addr)
        assert info.routable_beyond_as is False
