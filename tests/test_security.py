# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for border router security checks per Section 18."""

from ipv8lab.address import IPv8Address
from ipv8lab.packet import IPv8Packet
from ipv8lab.security import IngressFilter, Severity, check_bgp8_prefix_length


def _pkt(src: str, dst: str) -> IPv8Packet:
    return IPv8Packet(
        src=IPv8Address.parse(src),
        dst=IPv8Address.parse(dst),
    )


class TestIngressFilter:
    def test_valid_packet_no_violations(self):
        filt = IngressFilter(peer_asn=64496)
        pkt = _pkt("64496-192.0.2.1", "64497-198.51.100.7")
        assert filt.check(pkt) == []

    def test_asn_spoofing(self):
        filt = IngressFilter(peer_asn=64496)
        pkt = _pkt("64497-192.0.2.1", "64496-10.0.0.1")  # src ASN != peer
        violations = filt.check(pkt)
        assert len(violations) == 1
        assert violations[0].section == "18.1"
        assert violations[0].severity == Severity.SEC_ALERT

    def test_ipv4_compat_bypasses_asn_check(self):
        filt = IngressFilter(peer_asn=64496)
        pkt = _pkt("0.0.0.0.192.168.1.1", "64496-10.0.0.1")
        violations = filt.check(pkt)
        assert not any(v.section == "18.1" for v in violations)

    def test_internal_zone_source(self):
        filt = IngressFilter(peer_asn=64496)
        pkt = _pkt("127.1.0.0.10.0.0.1", "64496-10.0.0.1")
        violations = filt.check(pkt)
        assert any(v.section == "18.2" for v in violations)

    def test_internal_zone_destination(self):
        filt = IngressFilter(peer_asn=64496)
        pkt = _pkt("64496-10.0.0.1", "127.2.0.0.10.0.0.1")
        violations = filt.check(pkt)
        assert any(v.section == "18.2" for v in violations)

    def test_rine_source(self):
        filt = IngressFilter(peer_asn=64496)
        pkt = _pkt("100.0.0.1.10.0.0.1", "64496-10.0.0.1")
        violations = filt.check(pkt)
        assert any(v.section == "18.3" for v in violations)

    def test_rine_destination(self):
        filt = IngressFilter(peer_asn=64496)
        pkt = _pkt("64496-10.0.0.1", "100.0.0.2.10.0.0.1")
        violations = filt.check(pkt)
        assert any(v.section == "18.3" for v in violations)

    def test_interior_link_source(self):
        filt = IngressFilter(peer_asn=64496)
        pkt = _pkt("64496-222.0.0.1", "64497-10.0.0.1")
        violations = filt.check(pkt)
        assert any(v.section == "18.4" for v in violations)

    def test_interior_link_destination(self):
        filt = IngressFilter(peer_asn=64496)
        pkt = _pkt("64496-10.0.0.1", "64497-222.0.0.1")
        violations = filt.check(pkt)
        assert any(v.section == "18.4" for v in violations)

    def test_multicast_protocol_filtering(self):
        filt = IngressFilter(peer_asn=64496)
        # OSPF8 multicast prefix ff.ff.00.01
        pkt = _pkt("64496-10.0.0.1", "255.255.0.1.224.0.0.5")
        violations = filt.check(pkt)
        assert any(v.section == "18.6" for v in violations)

    def test_general_multicast_not_filtered(self):
        filt = IngressFilter(peer_asn=64496)
        # General cross-ASN multicast ff.ff.00.00 — NOT in filtered set
        pkt = _pkt("64496-10.0.0.1", "255.255.0.0.224.0.0.1")
        violations = filt.check(pkt)
        assert not any(v.section == "18.6" for v in violations)

    def test_internal_interface_no_external_checks(self):
        filt = IngressFilter(peer_asn=64496, is_external=False)
        pkt = _pkt("127.1.0.0.10.0.0.1", "127.2.0.0.10.0.0.2")
        violations = filt.check(pkt)
        assert violations == []

    def test_multiple_violations(self):
        filt = IngressFilter(peer_asn=64496)
        # src: wrong ASN + interior link; dst: internal zone
        pkt = _pkt("64497-222.0.0.1", "127.1.0.0.10.0.0.1")
        violations = filt.check(pkt)
        sections = {v.section for v in violations}
        assert "18.1" in sections  # ASN spoofing
        assert "18.4" in sections  # interior link src
        assert "18.2" in sections  # internal zone dst
        assert all(v.severity == Severity.SEC_ALERT for v in violations)


class TestBGP8PrefixLength:
    def test_valid_slash16(self):
        assert check_bgp8_prefix_length("0.0.251.240/16") is None

    def test_valid_slash8(self):
        assert check_bgp8_prefix_length("0.0.251.0/8") is None

    def test_too_specific_slash24(self):
        v = check_bgp8_prefix_length("0.0.251.240/24")
        assert v is not None
        assert v.section == "18.7"
        assert "/16" in v.message

    def test_too_specific_slash32(self):
        v = check_bgp8_prefix_length("0.0.251.240/32")
        assert v is not None

    def test_no_cidr(self):
        assert check_bgp8_prefix_length("0.0.251.240") is None

    def test_invalid_format(self):
        assert check_bgp8_prefix_length("0.0.251.240/abc") is None
