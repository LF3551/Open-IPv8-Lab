# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""IPv8 packet fragmentation and reassembly.

Follows the IPv4 fragmentation model adapted for the 28-byte IPv8 header:

- **Identification**: 16-bit value shared across all fragments of one original
  packet.
- **Flags** (3 bits):
  - bit 0: Reserved (must be 0)
  - bit 1: DF — Don't Fragment
  - bit 2: MF — More Fragments (1 = more fragments follow, 0 = last fragment)
- **Fragment Offset**: 13-bit value in 8-octet units indicating where in the
  original payload this fragment's data belongs.

MTU includes the 28-byte header, so the maximum payload per fragment is
``mtu - 28`` bytes, rounded down to a multiple of 8.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from ipv8lab.packet import HEADER_SIZE, IPv8Packet

# --- Flag constants ---

FLAG_RESERVED = 0b100
FLAG_DF = 0b010  # Don't Fragment
FLAG_MF = 0b001  # More Fragments

# Fragment offset unit in bytes (same as IPv4)
FRAG_UNIT = 8

# Default MTU (header + payload)
DEFAULT_MTU = 1500

# Minimum MTU: header + at least one fragment unit
MIN_MTU = HEADER_SIZE + FRAG_UNIT  # 36

# Maximum number of fragments to accept per reassembly buffer
MAX_FRAGMENTS = 8192

# Reassembly timeout (seconds)
REASSEMBLY_TIMEOUT = 30.0


class FragmentationError(Exception):
    """Raised on fragmentation failures."""


class ReassemblyError(Exception):
    """Raised on reassembly failures."""


# ---------------------------------------------------------------------------
# Fragmentation
# ---------------------------------------------------------------------------


def fragment(
    packet: IPv8Packet,
    mtu: int = DEFAULT_MTU,
    *,
    identification: int | None = None,
) -> list[IPv8Packet]:
    """Fragment an IPv8 packet into pieces fitting *mtu*.

    Returns a list of one or more ``IPv8Packet`` instances.  If the packet
    already fits within *mtu*, a single-element list is returned with the
    original packet's data (MF=0).

    Raises ``FragmentationError`` if the DF flag is set and the packet
    exceeds *mtu*.
    """
    if mtu < MIN_MTU:
        raise FragmentationError(f"MTU {mtu} is below minimum {MIN_MTU}")

    total_size = HEADER_SIZE + len(packet.payload)

    # Fits without fragmentation
    if total_size <= mtu:
        return [packet]

    # DF flag set — cannot fragment
    if packet.flags & FLAG_DF:
        raise FragmentationError(
            f"Packet size {total_size} exceeds MTU {mtu} and DF flag is set"
        )

    ident = identification if identification is not None else packet.identification

    max_payload = mtu - HEADER_SIZE
    # Round down to 8-byte boundary
    max_payload = (max_payload // FRAG_UNIT) * FRAG_UNIT
    if max_payload == 0:
        raise FragmentationError("MTU too small for any payload")

    fragments: list[IPv8Packet] = []
    data = packet.payload
    offset = 0

    while offset < len(data):
        chunk = data[offset : offset + max_payload]
        is_last = (offset + len(chunk)) >= len(data)

        frag_flags = packet.flags & FLAG_RESERVED  # preserve reserved bit
        if not is_last:
            frag_flags |= FLAG_MF

        frag_pkt = IPv8Packet(
            src=packet.src,
            dst=packet.dst,
            payload=chunk,
            version=packet.version,
            ihl=packet.ihl,
            tos=packet.tos,
            identification=ident,
            flags=frag_flags,
            fragment_offset=offset // FRAG_UNIT,
            ttl=packet.ttl,
            protocol=packet.protocol,
        )
        fragments.append(frag_pkt)
        offset += len(chunk)

    return fragments


def needs_fragmentation(packet: IPv8Packet, mtu: int = DEFAULT_MTU) -> bool:
    """Return True if the packet exceeds *mtu* and would need fragmentation."""
    return (HEADER_SIZE + len(packet.payload)) > mtu


def can_fragment(packet: IPv8Packet) -> bool:
    """Return True if the packet does NOT have the DF flag set."""
    return not bool(packet.flags & FLAG_DF)


def is_fragment(packet: IPv8Packet) -> bool:
    """Return True if the packet is a fragment (MF set or offset > 0)."""
    return bool(packet.flags & FLAG_MF) or packet.fragment_offset > 0


# ---------------------------------------------------------------------------
# Reassembly
# ---------------------------------------------------------------------------


@dataclass
class _ReassemblyBuffer:
    """Internal buffer collecting fragments for one (src, dst, id, proto) key."""

    fragments: dict[int, bytes] = field(default_factory=dict)  # offset→data
    total_length: int | None = None  # set when last fragment arrives
    created: float = field(default_factory=time.monotonic)

    @property
    def complete(self) -> bool:
        if self.total_length is None:
            return False
        # Check contiguous coverage from 0 to total_length
        covered = 0
        for off in sorted(self.fragments):
            if off > covered:
                return False  # gap
            end = off + len(self.fragments[off])
            if end > covered:
                covered = end
        return covered >= self.total_length


_ReassemblyKey = tuple[str, str, int, int]  # (src, dst, identification, protocol)


class Reassembler:
    """Stateful IPv8 fragment reassembler.

    Collects fragments keyed by ``(src, dst, identification, protocol)``
    and returns a fully reassembled packet when all pieces arrive.

    Usage::

        ra = Reassembler()
        for pkt in incoming_packets:
            result = ra.process(pkt)
            if result is not None:
                # result is the reassembled IPv8Packet
                handle(result)
    """

    def __init__(self, *, timeout: float = REASSEMBLY_TIMEOUT) -> None:
        self._buffers: dict[_ReassemblyKey, _ReassemblyBuffer] = {}
        self._timeout = timeout

    @property
    def pending(self) -> int:
        """Number of incomplete reassembly buffers."""
        return len(self._buffers)

    def process(self, packet: IPv8Packet) -> IPv8Packet | None:
        """Feed a packet (or fragment) into the reassembler.

        Returns the reassembled ``IPv8Packet`` when all fragments are
        collected, or ``None`` if the packet is a fragment still awaiting
        more pieces.

        Non-fragmented packets are returned as-is.
        """
        self._expire()

        if not is_fragment(packet):
            return packet

        key = self._key(packet)
        buf = self._buffers.get(key)
        if buf is None:
            buf = _ReassemblyBuffer()
            self._buffers[key] = buf

        if len(buf.fragments) >= MAX_FRAGMENTS:
            raise ReassemblyError(
                f"Too many fragments for key {key} (max {MAX_FRAGMENTS})"
            )

        byte_offset = packet.fragment_offset * FRAG_UNIT
        buf.fragments[byte_offset] = packet.payload

        # Last fragment? Compute total length
        if not (packet.flags & FLAG_MF):
            buf.total_length = byte_offset + len(packet.payload)

        if buf.complete:
            assert buf.total_length is not None
            reassembled = self._assemble(packet, buf)
            del self._buffers[key]
            return reassembled

        return None

    def flush(self) -> list[_ReassemblyKey]:
        """Remove all pending buffers and return their keys."""
        keys = list(self._buffers.keys())
        self._buffers.clear()
        return keys

    def expire(self) -> list[_ReassemblyKey]:
        """Remove timed-out buffers and return their keys."""
        return self._expire()

    # --- internals ---

    @staticmethod
    def _key(packet: IPv8Packet) -> _ReassemblyKey:
        return (str(packet.src), str(packet.dst), packet.identification, packet.protocol)

    def _expire(self) -> list[_ReassemblyKey]:
        now = time.monotonic()
        expired: list[_ReassemblyKey] = []
        for key, buf in list(self._buffers.items()):
            if now - buf.created > self._timeout:
                expired.append(key)
                del self._buffers[key]
        return expired

    @staticmethod
    def _assemble(template: IPv8Packet, buf: _ReassemblyBuffer) -> IPv8Packet:
        assert buf.total_length is not None
        payload = bytearray(buf.total_length)
        for off, data in sorted(buf.fragments.items()):
            payload[off : off + len(data)] = data
        return IPv8Packet(
            src=template.src,
            dst=template.dst,
            payload=bytes(payload),
            version=template.version,
            ihl=template.ihl,
            tos=template.tos,
            identification=template.identification,
            flags=0,  # reassembled: no MF, no DF
            fragment_offset=0,
            ttl=template.ttl,
            protocol=template.protocol,
        )


# ---------------------------------------------------------------------------
# Helper: fragment + reassemble round-trip
# ---------------------------------------------------------------------------


def fragment_and_reassemble(
    packet: IPv8Packet,
    mtu: int = DEFAULT_MTU,
) -> IPv8Packet:
    """Fragment a packet and immediately reassemble it (validation helper)."""
    frags = fragment(packet, mtu)
    ra = Reassembler()
    for frag in frags:
        result = ra.process(frag)
        if result is not None:
            return result
    raise ReassemblyError("Reassembly incomplete after all fragments processed")
