# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""UDP transport layer for IPv8 Lab — send/receive packets over real UDP sockets."""

from __future__ import annotations

import asyncio
import logging
import socket
import struct
from dataclasses import dataclass
from typing import Callable

from ipv8lab.packet import IPv8Packet

log = logging.getLogger(__name__)

# 4-byte magic prefix so we can distinguish IPv8 Lab frames on the wire
MAGIC = b"IV8L"
FRAME_HEADER = struct.Struct("!4sI")  # magic + length


def frame_packet(raw: bytes) -> bytes:
    """Wrap raw packet bytes in a UDP frame: MAGIC + length + data."""
    return FRAME_HEADER.pack(MAGIC, len(raw)) + raw


def unframe_packet(data: bytes) -> bytes:
    """Strip the UDP frame header and return the raw packet bytes."""
    if len(data) < FRAME_HEADER.size:
        raise ValueError(f"Frame too short: {len(data)} bytes")
    magic, length = FRAME_HEADER.unpack(data[: FRAME_HEADER.size])
    if magic != MAGIC:
        raise ValueError(f"Bad magic: {magic!r}")
    payload = data[FRAME_HEADER.size : FRAME_HEADER.size + length]
    if len(payload) < length:
        raise ValueError(f"Frame truncated: expected {length}, got {len(payload)}")
    return payload


@dataclass(slots=True)
class UDPEndpoint:
    """A (host, port) pair identifying a UDP peer."""

    host: str = "127.0.0.1"
    port: int = 0

    @property
    def addr(self) -> tuple[str, int]:
        return (self.host, self.port)


class UDPTransport:
    """Async UDP transport — binds a local socket, sends/receives framed IPv8 Lab packets."""

    def __init__(
        self,
        local: UDPEndpoint,
        on_packet: Callable[[IPv8Packet, tuple[str, int]], None] | None = None,
    ) -> None:
        self.local = local
        self.on_packet = on_packet
        self._sock: socket.socket | None = None
        self._transport: asyncio.DatagramTransport | None = None
        self._protocol: _Protocol | None = None

    async def start(self, loop: asyncio.AbstractEventLoop | None = None) -> None:
        loop = loop or asyncio.get_running_loop()
        self._transport, self._protocol = await loop.create_datagram_endpoint(
            lambda: _Protocol(self),
            local_addr=self.local.addr,
        )
        # update local port if it was 0 (OS-assigned)
        actual = self._transport.get_extra_info("sockname")
        if actual:
            self.local.host, self.local.port = actual[0], actual[1]
        log.info("UDPTransport listening on %s:%d", self.local.host, self.local.port)

    def send(self, packet: IPv8Packet, remote: UDPEndpoint) -> None:
        if self._transport is None:
            raise RuntimeError("Transport not started")
        raw = packet.to_bytes()
        self._transport.sendto(frame_packet(raw), remote.addr)
        log.debug("Sent %d bytes to %s:%d", len(raw), remote.host, remote.port)

    def stop(self) -> None:
        if self._transport:
            self._transport.close()
            self._transport = None
        log.info("UDPTransport stopped")

    def _handle_datagram(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            raw = unframe_packet(data)
            pkt = IPv8Packet.from_bytes(raw)
        except Exception:
            log.warning("Dropped malformed datagram from %s:%d", *addr)
            return
        log.debug("Received packet from %s:%d", *addr)
        if self.on_packet:
            self.on_packet(pkt, addr)


class _Protocol(asyncio.DatagramProtocol):
    def __init__(self, transport: UDPTransport) -> None:
        self._udp = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self._udp._handle_datagram(data, addr)

    def error_received(self, exc: Exception) -> None:
        log.error("UDP error: %s", exc)
