# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for ipv8lab.transport — UDP framing and transport."""

import asyncio

import pytest

from ipv8lab.address import IPv8Address
from ipv8lab.packet import IPv8Packet
from ipv8lab.transport import UDPEndpoint, UDPTransport, frame_packet, unframe_packet


class TestFraming:
    def test_roundtrip(self):
        raw = b"some packet data"
        framed = frame_packet(raw)
        assert unframe_packet(framed) == raw

    def test_bad_magic(self):
        with pytest.raises(ValueError, match="Bad magic"):
            unframe_packet(b"BAD!" + b"\x00\x00\x00\x04" + b"data")

    def test_too_short(self):
        with pytest.raises(ValueError, match="too short"):
            unframe_packet(b"IV")

    def test_truncated(self):
        with pytest.raises(ValueError, match="truncated"):
            unframe_packet(b"IV8L" + b"\x00\x00\x00\x10" + b"short")


class TestUDPTransport:
    @pytest.mark.asyncio
    async def test_send_receive(self):
        received: list[IPv8Packet] = []
        event = asyncio.Event()

        def on_recv(pkt: IPv8Packet, addr: tuple[str, int]) -> None:
            received.append(pkt)
            event.set()

        sender = UDPTransport(UDPEndpoint(port=0))
        receiver = UDPTransport(UDPEndpoint(port=0), on_packet=on_recv)

        await sender.start()
        await receiver.start()

        try:
            src = IPv8Address.parse("64496.10.0.0.1")
            dst = IPv8Address.parse("64497.10.0.0.2")
            pkt = IPv8Packet(src=src, dst=dst, payload=b"udp-test")

            sender.send(pkt, receiver.local)
            await asyncio.wait_for(event.wait(), timeout=2.0)

            assert len(received) == 1
            assert received[0].payload == b"udp-test"
            assert received[0].src == src
            assert received[0].dst == dst
        finally:
            sender.stop()
            receiver.stop()
