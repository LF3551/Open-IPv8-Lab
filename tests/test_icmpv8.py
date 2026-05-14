# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for ICMPv8 per Section 9."""

import pytest

from ipv8lab.address import IPv8Address
from ipv8lab.icmpv8 import (
    ICMPV8_HEADER_SIZE,
    ICMPv8Message,
    ICMPv8Type,
    RedirectCode,
    TimeExceededCode,
    UnreachableCode,
    destination_unreachable,
    echo_reply,
    echo_request,
    redirect,
    time_exceeded,
)

SRC = IPv8Address.parse("64496.192.0.2.1")
DST = IPv8Address.parse("64497.198.51.100.7")


class TestEchoRequestReply:
    def test_echo_request_type(self):
        msg = echo_request(SRC, DST, identifier=1, sequence=1)
        assert msg.msg_type == ICMPv8Type.ECHO_REQUEST
        assert msg.code == 0

    def test_echo_reply_swaps_src_dst(self):
        req = echo_request(SRC, DST, identifier=42, sequence=3)
        rep = echo_reply(req)
        assert rep.msg_type == ICMPv8Type.ECHO_REPLY
        assert rep.src == DST
        assert rep.dst == SRC
        assert rep.identifier == 42
        assert rep.sequence == 3

    def test_echo_with_payload(self):
        req = echo_request(SRC, DST, payload=b"ping")
        rep = echo_reply(req)
        assert rep.payload == b"ping"

    def test_roundtrip_serialization(self):
        req = echo_request(SRC, DST, identifier=100, sequence=5, payload=b"test")
        raw = req.to_bytes()
        restored = ICMPv8Message.from_bytes(raw, src=SRC, dst=DST)
        assert restored.msg_type == ICMPv8Type.ECHO_REQUEST
        assert restored.identifier == 100
        assert restored.sequence == 5
        assert restored.payload == b"test"

    def test_checksum_mismatch(self):
        req = echo_request(SRC, DST, payload=b"data")
        raw = bytearray(req.to_bytes())
        raw[ICMPV8_HEADER_SIZE] ^= 0xFF  # corrupt payload
        with pytest.raises(ValueError, match="checksum"):
            ICMPv8Message.from_bytes(bytes(raw), src=SRC, dst=DST)

    def test_too_short(self):
        with pytest.raises(ValueError, match="too short"):
            ICMPv8Message.from_bytes(b"\x00" * 4, src=SRC, dst=DST)

    def test_header_size(self):
        assert ICMPV8_HEADER_SIZE == 8


class TestDestinationUnreachable:
    def test_net_unreachable(self):
        msg = destination_unreachable(SRC, DST, UnreachableCode.NET_UNREACHABLE)
        assert msg.msg_type == ICMPv8Type.DESTINATION_UNREACHABLE
        assert msg.code == UnreachableCode.NET_UNREACHABLE

    def test_asn_unreachable(self):
        msg = destination_unreachable(SRC, DST, UnreachableCode.ASN_UNREACHABLE)
        assert msg.code == UnreachableCode.ASN_UNREACHABLE

    def test_roundtrip(self):
        msg = destination_unreachable(SRC, DST, UnreachableCode.HOST_UNREACHABLE, b"err")
        raw = msg.to_bytes()
        restored = ICMPv8Message.from_bytes(raw, src=SRC, dst=DST)
        assert restored.msg_type == ICMPv8Type.DESTINATION_UNREACHABLE
        assert restored.code == UnreachableCode.HOST_UNREACHABLE
        assert restored.payload == b"err"


class TestTimeExceeded:
    def test_ttl_exceeded(self):
        msg = time_exceeded(SRC, DST, TimeExceededCode.TTL_EXCEEDED)
        assert msg.msg_type == ICMPv8Type.TIME_EXCEEDED
        assert msg.code == TimeExceededCode.TTL_EXCEEDED

    def test_roundtrip(self):
        msg = time_exceeded(SRC, DST, TimeExceededCode.FRAGMENT_REASSEMBLY, b"frag")
        raw = msg.to_bytes()
        restored = ICMPv8Message.from_bytes(raw, src=SRC, dst=DST)
        assert restored.code == TimeExceededCode.FRAGMENT_REASSEMBLY
        assert restored.payload == b"frag"


class TestRedirect:
    def test_network_redirect(self):
        msg = redirect(SRC, DST, RedirectCode.NETWORK)
        assert msg.msg_type == ICMPv8Type.REDIRECT
        assert msg.code == RedirectCode.NETWORK

    def test_host_redirect(self):
        msg = redirect(SRC, DST, RedirectCode.HOST)
        assert msg.code == RedirectCode.HOST


class TestAddresses:
    def test_64bit_addresses_preserved(self):
        req = echo_request(SRC, DST)
        assert req.src.to_int() == SRC.to_int()
        assert req.dst.to_int() == DST.to_int()

    def test_ipv4_compatible_addresses(self):
        s = IPv8Address.parse("0.0.0.0.10.0.0.1")
        d = IPv8Address.parse("0.0.0.0.10.0.0.2")
        req = echo_request(s, d)
        rep = echo_reply(req)
        assert rep.src == d
        assert rep.dst == s

    def test_internal_zone_addresses(self):
        s = IPv8Address.parse("127.1.0.0.10.0.0.1")
        d = IPv8Address.parse("127.1.0.0.10.0.0.2")
        msg = echo_request(s, d)
        raw = msg.to_bytes()
        restored = ICMPv8Message.from_bytes(raw, src=s, dst=d)
        assert restored.src == s
