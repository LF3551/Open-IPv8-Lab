# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for 8to4 tunnelling per Section 13.3."""

import pytest

from ipv8lab.address import IPv8Address
from ipv8lab.packet import IPv8Packet
from ipv8lab.tunnel import (
    TunnelEndpoint,
    TunnelFrame,
    decapsulate,
    encapsulate,
    is_8to4_frame,
)

SRC = IPv8Address.parse("64496-192.0.2.1")
DST = IPv8Address.parse("64497-198.51.100.7")


@pytest.fixture()
def pkt() -> IPv8Packet:
    return IPv8Packet(src=SRC, dst=DST, payload=b"hello tunnel")


class TestEncapsulateDecapsulate:
    def test_roundtrip(self, pkt: IPv8Packet):
        frame_bytes = encapsulate(pkt)
        frame = decapsulate(frame_bytes)
        assert frame.packet.src == SRC
        assert frame.packet.dst == DST
        assert frame.packet.payload == b"hello tunnel"
        assert frame.encrypted is False

    def test_encrypted_flag(self, pkt: IPv8Packet):
        frame_bytes = encapsulate(pkt, encrypted=True)
        frame = decapsulate(frame_bytes)
        assert frame.encrypted is True

    def test_magic_header(self, pkt: IPv8Packet):
        frame_bytes = encapsulate(pkt)
        assert frame_bytes[:4] == b"8TO4"

    def test_empty_payload_packet(self):
        pkt = IPv8Packet(src=SRC, dst=DST)
        frame_bytes = encapsulate(pkt)
        frame = decapsulate(frame_bytes)
        assert frame.packet.payload == b""


class TestDecapsulateErrors:
    def test_too_short(self):
        with pytest.raises(ValueError, match="too short"):
            decapsulate(b"\x00\x00")

    def test_bad_magic(self):
        with pytest.raises(ValueError, match="magic"):
            decapsulate(b"XXXX\x00\x00\x00\x1c" + b"\x00" * 28)

    def test_truncated_payload(self, pkt: IPv8Packet):
        frame_bytes = encapsulate(pkt)
        with pytest.raises(ValueError, match="truncated"):
            decapsulate(frame_bytes[:12])


class TestIs8to4Frame:
    def test_valid(self, pkt: IPv8Packet):
        assert is_8to4_frame(encapsulate(pkt))

    def test_invalid(self):
        assert not is_8to4_frame(b"\x00\x00\x00\x00")

    def test_too_short(self):
        assert not is_8to4_frame(b"8T")


class TestTunnelEndpoint:
    def test_defaults(self):
        ep = TunnelEndpoint(ipv4_address="10.0.0.1")
        assert ep.port == 8418

    def test_custom_port(self):
        ep = TunnelEndpoint(ipv4_address="10.0.0.1", port=9999)
        assert ep.port == 9999


class TestTunnelFrame:
    def test_frame_fields(self, pkt: IPv8Packet):
        ep_src = TunnelEndpoint("10.0.0.1")
        ep_dst = TunnelEndpoint("10.0.0.2")
        frame = TunnelFrame(
            packet=pkt, encrypted=True,
            src_endpoint=ep_src, dst_endpoint=ep_dst,
        )
        assert frame.src_endpoint is not None
        assert frame.dst_endpoint is not None
        assert frame.encrypted is True
