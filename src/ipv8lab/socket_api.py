# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Socket API Compatibility mock per draft-thain-ipv8- Section 6.2.

Provides AF_INET8, sockaddr_in8, and a mock IPv8 socket that
transparently handles r.r.r.r prefix management for legacy AF_INET
applications and new AF_INET8 applications.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

from ipv8lab.address import IPv8Address


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

AF_INET = socket.AF_INET        # 2
AF_INET8 = 46                   # Address family for IPv8 (spec §6, IANA-provisional)


class SocketType(IntEnum):
    SOCK_STREAM = socket.SOCK_STREAM
    SOCK_DGRAM = socket.SOCK_DGRAM


# ---------------------------------------------------------------------------
# sockaddr_in8 — Section 6.2
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class SockaddrIn8:
    """``struct sockaddr_in8`` per Section 6.2.

    Fields:
        sin8_family: AF_INET8 (46)
        sin8_port:   port number (0-65535)
        sin8_rn:     Routing Number (RN) as uint32  [was sin8_asn]
        sin8_addr:   n.n.n.n host address as dotted-quad string
    """

    sin8_family: int = AF_INET8
    sin8_port: int = 0
    sin8_rn: int = 0
    sin8_addr: str = "0.0.0.0"

    @property
    def sin8_asn(self) -> int:
        """Backwards-compatible alias for :attr:`sin8_rn`."""
        return self.sin8_rn

    def to_ipv8_address(self) -> IPv8Address:
        """Convert to an IPv8Address."""
        return IPv8Address.parse(f"{self.sin8_rn}.{self.sin8_addr}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "sin8_family": self.sin8_family,
            "sin8_port": self.sin8_port,
            "sin8_rn": self.sin8_rn,
            "sin8_addr": self.sin8_addr,
        }

    @classmethod
    def from_ipv8_address(cls, addr: IPv8Address, port: int = 0) -> SockaddrIn8:
        """Create from an IPv8Address and port."""
        return cls(
            sin8_family=AF_INET8,
            sin8_port=port,
            sin8_rn=addr.rn,
            sin8_addr=addr.host_str,
        )

    @classmethod
    def from_ipv4_tuple(cls, addr_tuple: tuple[str, int], asn: int = 0) -> SockaddrIn8:
        """Create from a legacy (host, port) tuple with optional RN.

        The *asn* parameter is kept for backwards compatibility; it maps
        directly to :attr:`sin8_rn`.
        """
        host, port = addr_tuple
        return cls(
            sin8_family=AF_INET8,
            sin8_port=port,
            sin8_rn=asn,
            sin8_addr=host,
        )


# ---------------------------------------------------------------------------
# sockaddr_in (legacy, for comparison)
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class SockaddrIn:
    """Legacy ``struct sockaddr_in`` (AF_INET)."""

    sin_family: int = AF_INET
    sin_port: int = 0
    sin_addr: str = "0.0.0.0"


# ---------------------------------------------------------------------------
# Compatibility layer — transparent r.r.r.r management
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class CompatLayer:
    """IPv8 socket compatibility layer (Section 16).

    Intercepts AF_INET socket calls and transparently manages
    r.r.r.r via DNS8 interception and XLATE8.
    """

    default_asn: int = 0
    _xlate_table: dict[str, int] = field(default_factory=dict)

    def register_dns8(self, host: str, asn: int) -> None:
        """Simulate DNS8 A8 record: map *host* → ASN prefix."""
        self._xlate_table[host] = asn

    def resolve(self, host: str) -> int:
        """Resolve host → ASN via DNS8 cache; fall back to default."""
        return self._xlate_table.get(host, self.default_asn)

    def upgrade_connect(self, addr: tuple[str, int]) -> SockaddrIn8:
        """Upgrade a legacy ``connect(host, port)`` to sockaddr_in8.

        Transparently prepends RN from DNS8 resolution.
        """
        host, port = addr
        asn = self.resolve(host)
        return SockaddrIn8(
            sin8_family=AF_INET8,
            sin8_port=port,
            sin8_rn=asn,
            sin8_addr=host,
        )

    def downgrade_to_ipv4(self, sa8: SockaddrIn8) -> SockaddrIn:
        """Strip r.r.r.r — produce a legacy sockaddr_in."""
        return SockaddrIn(
            sin_family=AF_INET,
            sin_port=sa8.sin8_port,
            sin_addr=sa8.sin8_addr,
        )


# ---------------------------------------------------------------------------
# Mock IPv8 socket
# ---------------------------------------------------------------------------

@dataclass
class SocketEvent:
    """Recorded socket operation for inspection."""

    action: str
    family: int
    address: SockaddrIn8 | SockaddrIn | None = None
    data: bytes | None = None


@dataclass
class IPv8Socket:
    """Mock IPv8 socket supporting AF_INET and AF_INET8.

    Not a real network socket — records operations for testing and
    simulation purposes.
    """

    family: int = AF_INET8
    sock_type: int = SocketType.SOCK_STREAM
    compat: CompatLayer = field(default_factory=CompatLayer)
    _bound: SockaddrIn8 | None = None
    _connected: SockaddrIn8 | None = None
    _events: list[SocketEvent] = field(default_factory=list)

    # -- lifecycle -----------------------------------------------------------

    def bind(self, address: SockaddrIn8 | tuple[str, int]) -> None:
        sa8 = self._coerce(address)
        self._bound = sa8
        self._events.append(SocketEvent("bind", self.family, sa8))

    def connect(self, address: SockaddrIn8 | tuple[str, int]) -> None:
        sa8 = self._coerce(address)
        self._connected = sa8
        self._events.append(SocketEvent("connect", self.family, sa8))

    def send(self, data: bytes) -> int:
        self._events.append(
            SocketEvent("send", self.family, self._connected, data)
        )
        return len(data)

    def recv(self, _bufsize: int = 4096) -> bytes:
        self._events.append(SocketEvent("recv", self.family, self._connected))
        return b""

    def close(self) -> None:
        self._events.append(SocketEvent("close", self.family))
        self._bound = None
        self._connected = None

    # -- helpers -------------------------------------------------------------

    @property
    def local_address(self) -> SockaddrIn8 | None:
        return self._bound

    @property
    def remote_address(self) -> SockaddrIn8 | None:
        return self._connected

    @property
    def events(self) -> list[SocketEvent]:
        return list(self._events)

    def _coerce(self, address: SockaddrIn8 | tuple[str, int]) -> SockaddrIn8:
        """Coerce legacy (host, port) to sockaddr_in8 via compat layer."""
        if isinstance(address, SockaddrIn8):
            return address
        return self.compat.upgrade_connect(address)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def create_socket(
    family: int = AF_INET8,
    sock_type: int = SocketType.SOCK_STREAM,
    default_asn: int = 0,
) -> IPv8Socket:
    """Create a mock IPv8 socket."""
    return IPv8Socket(
        family=family,
        sock_type=sock_type,
        compat=CompatLayer(default_asn=default_asn),
    )
