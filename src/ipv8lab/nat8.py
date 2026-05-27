# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""NAT8 — IPv8 Network Address Translation gateway simulation.

Implements three NAT modes adapted for 64-bit IPv8 addresses:

* **Static NAT** — one-to-one mapping between an internal and an external
  address.  Every packet from the internal host is rewritten with the
  configured external address and vice-versa.

* **Dynamic NAT** — allocates external addresses from a pool on demand.
  When an internal host sends its first packet, an unused address from the
  pool is assigned; the mapping persists until explicitly released or the
  idle timer expires.

* **PAT (Port Address Translation / Overload)** — many internal hosts share
  a single external address distinguished by port numbers.  Each
  ``(internal_addr, internal_port)`` pair gets a unique external port.

All modes support:

- Egress rewriting (internal → external)
- Ingress reverse rewriting (external → internal)
- Session-level statistics
- JSON-serialisable state
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum

from ipv8lab.address import IPv8Address
from ipv8lab.packet import IPv8Packet


# ---------------------------------------------------------------------------
# NAT mode
# ---------------------------------------------------------------------------


class NATMode(str, Enum):
    STATIC = "static"
    DYNAMIC = "dynamic"
    PAT = "pat"


# ---------------------------------------------------------------------------
# Mapping entries
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class NATMapping:
    """A single NAT mapping entry."""

    internal_addr: IPv8Address
    external_addr: IPv8Address
    internal_port: int = 0
    external_port: int = 0
    mode: NATMode = NATMode.STATIC
    created: float = 0.0
    last_used: float = 0.0
    packets_out: int = 0
    packets_in: int = 0

    def touch(self) -> None:
        self.last_used = time.monotonic()

    def to_dict(self) -> dict[str, object]:
        return {
            "internal_addr": str(self.internal_addr),
            "external_addr": str(self.external_addr),
            "internal_port": self.internal_port,
            "external_port": self.external_port,
            "mode": self.mode.value,
            "packets_out": self.packets_out,
            "packets_in": self.packets_in,
        }


# ---------------------------------------------------------------------------
# NAT Gateway
# ---------------------------------------------------------------------------

# Default idle timeout for dynamic / PAT entries (seconds)
DEFAULT_IDLE_TIMEOUT = 300.0

# PAT port range
PAT_PORT_MIN = 10000
PAT_PORT_MAX = 65535


@dataclass(slots=True)
class NATStats:
    """Aggregate NAT gateway statistics."""

    total_egress: int = 0
    total_ingress: int = 0
    total_dropped: int = 0
    active_mappings: int = 0
    pool_available: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "total_egress": self.total_egress,
            "total_ingress": self.total_ingress,
            "total_dropped": self.total_dropped,
            "active_mappings": self.active_mappings,
            "pool_available": self.pool_available,
        }


class NATGateway:
    """IPv8 NAT gateway supporting static, dynamic, and PAT modes.

    Usage::

        gw = NATGateway(mode=NATMode.DYNAMIC)
        gw.add_pool_address("64496-10.0.0.100")
        gw.add_pool_address("64496-10.0.0.101")

        translated = gw.translate_egress(packet)
        original   = gw.translate_ingress(response)
    """

    def __init__(
        self,
        mode: NATMode = NATMode.STATIC,
        *,
        idle_timeout: float = DEFAULT_IDLE_TIMEOUT,
        pat_address: str | IPv8Address | None = None,
        clock: object | None = None,
    ) -> None:
        self._mode = mode
        self._idle_timeout = idle_timeout
        self._clock = clock if clock is not None else time.monotonic

        # Static & dynamic: internal_addr_str → mapping
        self._mappings: dict[str, NATMapping] = {}

        # Dynamic pool of available external addresses
        self._pool: list[IPv8Address] = []
        self._pool_used: set[str] = set()

        # PAT: (internal_addr_str, internal_port) → mapping
        self._pat_mappings: dict[tuple[str, int], NATMapping] = {}
        self._pat_reverse: dict[int, tuple[str, int]] = {}  # ext_port → key
        self._pat_address: IPv8Address | None = None
        if pat_address is not None:
            if isinstance(pat_address, str):
                pat_address = IPv8Address.parse(pat_address)
            self._pat_address = pat_address
        self._next_pat_port = PAT_PORT_MIN

        # Stats
        self._stats = NATStats()

    # ---- properties ----

    @property
    def mode(self) -> NATMode:
        return self._mode

    @property
    def mapping_count(self) -> int:
        if self._mode == NATMode.PAT:
            return len(self._pat_mappings)
        return len(self._mappings)

    @property
    def pool_size(self) -> int:
        return len(self._pool)

    @property
    def pool_available(self) -> int:
        return len(self._pool) - len(self._pool_used)

    # ---- configuration ----

    def add_static_mapping(
        self,
        internal: str | IPv8Address,
        external: str | IPv8Address,
    ) -> NATMapping:
        """Add a static one-to-one NAT mapping."""
        if isinstance(internal, str):
            internal = IPv8Address.parse(internal)
        if isinstance(external, str):
            external = IPv8Address.parse(external)

        now: float = self._clock()  # type: ignore[operator]
        m = NATMapping(
            internal_addr=internal, external_addr=external,
            mode=NATMode.STATIC, created=now, last_used=now,
        )
        self._mappings[str(internal)] = m
        return m

    def add_pool_address(self, addr: str | IPv8Address) -> None:
        """Add an external address to the dynamic NAT pool."""
        if isinstance(addr, str):
            addr = IPv8Address.parse(addr)
        self._pool.append(addr)

    def set_pat_address(self, addr: str | IPv8Address) -> None:
        """Set the single external address used for PAT/overload."""
        if isinstance(addr, str):
            addr = IPv8Address.parse(addr)
        self._pat_address = addr

    # ---- egress (internal → external) ----

    def translate_egress(
        self,
        packet: IPv8Packet,
        src_port: int = 0,
    ) -> IPv8Packet | None:
        """Translate the source address of an outgoing packet.

        Returns a new packet with rewritten source, or ``None`` if
        no mapping could be established.
        """
        self._expire()

        if self._mode == NATMode.PAT:
            return self._egress_pat(packet, src_port)

        key = str(packet.src)
        mapping = self._mappings.get(key)

        if mapping is None and self._mode == NATMode.DYNAMIC:
            mapping = self._allocate_dynamic(packet.src)

        if mapping is None:
            self._stats.total_dropped += 1
            return None

        mapping.packets_out += 1
        mapping.last_used = self._clock()  # type: ignore[operator]
        self._stats.total_egress += 1

        return IPv8Packet(
            src=mapping.external_addr,
            dst=packet.dst,
            payload=packet.payload,
            version=packet.version,
            ihl=packet.ihl,
            tos=packet.tos,
            identification=packet.identification,
            flags=packet.flags,
            fragment_offset=packet.fragment_offset,
            ttl=packet.ttl,
            protocol=packet.protocol,
        )

    def translate_ingress(
        self,
        packet: IPv8Packet,
        dst_port: int = 0,
    ) -> IPv8Packet | None:
        """Translate the destination of an incoming packet back to internal.

        Returns a new packet with rewritten destination, or ``None``.
        """
        self._expire()

        if self._mode == NATMode.PAT:
            return self._ingress_pat(packet, dst_port)

        # Reverse lookup: find mapping where external == packet.dst
        mapping = self._reverse_lookup(str(packet.dst))
        if mapping is None:
            self._stats.total_dropped += 1
            return None

        mapping.packets_in += 1
        mapping.last_used = self._clock()  # type: ignore[operator]
        self._stats.total_ingress += 1

        return IPv8Packet(
            src=packet.src,
            dst=mapping.internal_addr,
            payload=packet.payload,
            version=packet.version,
            ihl=packet.ihl,
            tos=packet.tos,
            identification=packet.identification,
            flags=packet.flags,
            fragment_offset=packet.fragment_offset,
            ttl=packet.ttl,
            protocol=packet.protocol,
        )

    # ---- PAT specifics ----

    def _egress_pat(self, packet: IPv8Packet, src_port: int) -> IPv8Packet | None:
        if self._pat_address is None:
            self._stats.total_dropped += 1
            return None

        key = (str(packet.src), src_port)
        mapping = self._pat_mappings.get(key)

        if mapping is None:
            ext_port = self._alloc_pat_port()
            if ext_port is None:
                self._stats.total_dropped += 1
                return None
            now: float = self._clock()  # type: ignore[operator]
            mapping = NATMapping(
                internal_addr=packet.src,
                external_addr=self._pat_address,
                internal_port=src_port,
                external_port=ext_port,
                mode=NATMode.PAT,
                created=now, last_used=now,
            )
            self._pat_mappings[key] = mapping
            self._pat_reverse[ext_port] = key

        mapping.packets_out += 1
        mapping.last_used = self._clock()  # type: ignore[operator]
        self._stats.total_egress += 1

        return IPv8Packet(
            src=self._pat_address,
            dst=packet.dst,
            payload=packet.payload,
            version=packet.version,
            ihl=packet.ihl,
            tos=packet.tos,
            identification=packet.identification,
            flags=packet.flags,
            fragment_offset=packet.fragment_offset,
            ttl=packet.ttl,
            protocol=packet.protocol,
        )

    def _ingress_pat(self, packet: IPv8Packet, dst_port: int) -> IPv8Packet | None:
        key_tuple = self._pat_reverse.get(dst_port)
        if key_tuple is None:
            self._stats.total_dropped += 1
            return None

        mapping = self._pat_mappings.get(key_tuple)
        if mapping is None:
            self._stats.total_dropped += 1
            return None

        mapping.packets_in += 1
        mapping.last_used = self._clock()  # type: ignore[operator]
        self._stats.total_ingress += 1

        return IPv8Packet(
            src=packet.src,
            dst=mapping.internal_addr,
            payload=packet.payload,
            version=packet.version,
            ihl=packet.ihl,
            tos=packet.tos,
            identification=packet.identification,
            flags=packet.flags,
            fragment_offset=packet.fragment_offset,
            ttl=packet.ttl,
            protocol=packet.protocol,
        )

    def _alloc_pat_port(self) -> int | None:
        start = self._next_pat_port
        while self._next_pat_port in self._pat_reverse:
            self._next_pat_port += 1
            if self._next_pat_port > PAT_PORT_MAX:
                self._next_pat_port = PAT_PORT_MIN
            if self._next_pat_port == start:
                return None  # exhausted
        port = self._next_pat_port
        self._next_pat_port += 1
        if self._next_pat_port > PAT_PORT_MAX:
            self._next_pat_port = PAT_PORT_MIN
        return port

    # ---- dynamic allocation ----

    def _allocate_dynamic(self, internal: IPv8Address) -> NATMapping | None:
        for addr in self._pool:
            if str(addr) not in self._pool_used:
                self._pool_used.add(str(addr))
                now: float = self._clock()  # type: ignore[operator]
                m = NATMapping(
                    internal_addr=internal, external_addr=addr,
                    mode=NATMode.DYNAMIC, created=now, last_used=now,
                )
                self._mappings[str(internal)] = m
                return m
        return None  # pool exhausted

    # ---- reverse lookup ----

    def _reverse_lookup(self, external_str: str) -> NATMapping | None:
        for m in self._mappings.values():
            if str(m.external_addr) == external_str:
                return m
        return None

    # ---- expiry ----

    def _expire(self) -> None:
        if self._mode == NATMode.STATIC:
            return
        now: float = self._clock()  # type: ignore[operator]
        if self._mode == NATMode.PAT:
            expired_keys = [
                k for k, m in self._pat_mappings.items()
                if now - m.last_used > self._idle_timeout
            ]
            for k in expired_keys:
                m = self._pat_mappings.pop(k)
                self._pat_reverse.pop(m.external_port, None)
        else:
            expired_keys_dyn = [
                k for k, m in self._mappings.items()
                if m.mode == NATMode.DYNAMIC and now - m.last_used > self._idle_timeout
            ]
            for dk in expired_keys_dyn:
                m = self._mappings.pop(dk)
                self._pool_used.discard(str(m.external_addr))

    # ---- release ----

    def release(self, internal: str | IPv8Address) -> bool:
        """Manually release a dynamic mapping."""
        if isinstance(internal, str):
            internal = IPv8Address.parse(internal)
        key = str(internal)
        m = self._mappings.pop(key, None)
        if m is None:
            return False
        if m.mode == NATMode.DYNAMIC:
            self._pool_used.discard(str(m.external_addr))
        return True

    def release_pat(self, internal: str | IPv8Address, port: int) -> bool:
        """Manually release a PAT mapping."""
        if isinstance(internal, str):
            internal = IPv8Address.parse(internal)
        key = (str(internal), port)
        m = self._pat_mappings.pop(key, None)
        if m is None:
            return False
        self._pat_reverse.pop(m.external_port, None)
        return True

    # ---- queries ----

    def get_mapping(self, internal: str | IPv8Address) -> NATMapping | None:
        if isinstance(internal, str):
            internal = IPv8Address.parse(internal)
        return self._mappings.get(str(internal))

    def get_pat_mapping(self, internal: str | IPv8Address, port: int) -> NATMapping | None:
        if isinstance(internal, str):
            internal = IPv8Address.parse(internal)
        return self._pat_mappings.get((str(internal), port))

    def all_mappings(self) -> list[NATMapping]:
        if self._mode == NATMode.PAT:
            return list(self._pat_mappings.values())
        return list(self._mappings.values())

    def stats(self) -> NATStats:
        s = self._stats
        s.active_mappings = self.mapping_count
        s.pool_available = self.pool_available
        return s

    def to_dict(self) -> dict[str, object]:
        return {
            "mode": self._mode.value,
            "mappings": [m.to_dict() for m in self.all_mappings()],
            "stats": self.stats().to_dict(),
        }

    # ---- reset ----

    def clear(self) -> None:
        """Remove all mappings and reset stats."""
        self._mappings.clear()
        self._pat_mappings.clear()
        self._pat_reverse.clear()
        self._pool_used.clear()
        self._next_pat_port = PAT_PORT_MIN
        self._stats = NATStats()
