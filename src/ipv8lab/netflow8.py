# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""NetFlow8 — Flow monitoring and telemetry export for IPv8 networks.

Implements a NetFlow v5-inspired flow collector adapted for 64-bit IPv8
addresses.  A *flow* is identified by a 5-tuple:

    (src_addr, dst_addr, protocol, src_port, dst_port)

The collector tracks per-flow packet/byte counters, first/last timestamps,
TOS and TTL values.  Expired flows are exported into *FlowRecord* objects
that can be serialised to JSON, binary, or fed into analytics pipelines.

Usage::

    collector = FlowCollector(active_timeout=60.0, idle_timeout=15.0)
    collector.observe(packet, src_port=80, dst_port=12345)
    ...
    records = collector.export_expired()
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass
from enum import IntEnum

from ipv8lab.address import IPv8Address
from ipv8lab.packet import IPv8Packet


# ---------------------------------------------------------------------------
# Flow key (5-tuple)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FlowKey:
    """Canonical 5-tuple identifying a single flow."""

    src_addr: IPv8Address
    dst_addr: IPv8Address
    protocol: int
    src_port: int = 0
    dst_port: int = 0

    def to_dict(self) -> dict[str, object]:
        return {
            "src_addr": str(self.src_addr),
            "dst_addr": str(self.dst_addr),
            "protocol": self.protocol,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
        }

    def reverse(self) -> FlowKey:
        """Return the reverse direction key."""
        return FlowKey(
            src_addr=self.dst_addr,
            dst_addr=self.src_addr,
            protocol=self.protocol,
            src_port=self.dst_port,
            dst_port=self.src_port,
        )


# ---------------------------------------------------------------------------
# Flow record (exported)
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class FlowRecord:
    """An exported (finalised) flow record."""

    key: FlowKey
    packets: int = 0
    octets: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    tos: int = 0
    min_ttl: int = 255
    max_ttl: int = 0
    tcp_flags: int = 0

    @property
    def duration(self) -> float:
        return max(0.0, self.last_ts - self.first_ts)

    def to_dict(self) -> dict[str, object]:
        d = self.key.to_dict()
        d.update({
            "packets": self.packets,
            "octets": self.octets,
            "first_ts": round(self.first_ts, 6),
            "last_ts": round(self.last_ts, 6),
            "duration": round(self.duration, 6),
            "tos": self.tos,
            "min_ttl": self.min_ttl,
            "max_ttl": self.max_ttl,
            "tcp_flags": self.tcp_flags,
        })
        return d


# ---------------------------------------------------------------------------
# Active flow entry (mutable, internal)
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _ActiveFlow:
    """Mutable flow entry tracked inside the collector."""

    key: FlowKey
    packets: int = 0
    octets: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    tos: int = 0
    min_ttl: int = 255
    max_ttl: int = 0
    tcp_flags: int = 0

    def update(self, pkt: IPv8Packet, ts: float) -> None:
        """Update the flow with a new packet."""
        size = len(pkt.payload) + 28  # header + payload
        self.packets += 1
        self.octets += size
        self.last_ts = ts
        if self.packets == 1:
            self.first_ts = ts
        self.tos = pkt.tos
        if pkt.ttl < self.min_ttl:
            self.min_ttl = pkt.ttl
        if pkt.ttl > self.max_ttl:
            self.max_ttl = pkt.ttl

    def to_record(self) -> FlowRecord:
        return FlowRecord(
            key=self.key,
            packets=self.packets,
            octets=self.octets,
            first_ts=self.first_ts,
            last_ts=self.last_ts,
            tos=self.tos,
            min_ttl=self.min_ttl,
            max_ttl=self.max_ttl,
            tcp_flags=self.tcp_flags,
        )


# ---------------------------------------------------------------------------
# Export format
# ---------------------------------------------------------------------------


class ExportFormat(IntEnum):
    """Supported export formats."""
    JSON = 0
    BINARY = 1


# Binary record format:
#   src_asn(4) + src_host(4) + dst_asn(4) + dst_host(4) = 16 bytes addresses
#   protocol(1) + tos(1) + min_ttl(1) + max_ttl(1) = 4
#   src_port(2) + dst_port(2) = 4
#   packets(4) + octets(4) = 8
#   first_ts(8d) + last_ts(8d) = 16
#   Total: 48 bytes per record
BINARY_RECORD_FMT = "!IIII BBBB HH II dd"
BINARY_RECORD_SIZE = struct.calcsize(BINARY_RECORD_FMT)

# File magic for .nf8 files
NF8_MAGIC = 0x4E463801  # "NF8\x01"
NF8_HEADER_FMT = "!IHH"  # magic(4) + version(2) + count(2)
NF8_HEADER_SIZE = struct.calcsize(NF8_HEADER_FMT)


def _addr_to_u32_pair(addr: IPv8Address) -> tuple[int, int]:
    """Convert IPv8Address to (asn_u32, host_u32)."""
    a = addr.routing_prefix
    h = addr.host_part
    asn_u32 = (a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3]
    host_u32 = (h[0] << 24) | (h[1] << 16) | (h[2] << 8) | h[3]
    return asn_u32, host_u32


def _u32_pair_to_addr(asn_u32: int, host_u32: int) -> IPv8Address:
    """Convert (asn_u32, host_u32) back to IPv8Address."""
    rp = (
        (asn_u32 >> 24) & 0xFF,
        (asn_u32 >> 16) & 0xFF,
        (asn_u32 >> 8) & 0xFF,
        asn_u32 & 0xFF,
    )
    hp = (
        (host_u32 >> 24) & 0xFF,
        (host_u32 >> 16) & 0xFF,
        (host_u32 >> 8) & 0xFF,
        host_u32 & 0xFF,
    )
    return IPv8Address(routing_prefix=rp, host_part=hp)


def encode_record(rec: FlowRecord) -> bytes:
    """Encode a FlowRecord to binary."""
    sa, sh = _addr_to_u32_pair(rec.key.src_addr)
    da, dh = _addr_to_u32_pair(rec.key.dst_addr)
    return struct.pack(
        BINARY_RECORD_FMT,
        sa, sh, da, dh,
        rec.key.protocol, rec.tos, rec.min_ttl, rec.max_ttl,
        rec.key.src_port, rec.key.dst_port,
        rec.packets, rec.octets,
        rec.first_ts, rec.last_ts,
    )


def decode_record(data: bytes) -> FlowRecord:
    """Decode a FlowRecord from binary."""
    (
        sa, sh, da, dh,
        proto, tos, min_ttl, max_ttl,
        sport, dport,
        packets, octets,
        first_ts, last_ts,
    ) = struct.unpack(BINARY_RECORD_FMT, data[:BINARY_RECORD_SIZE])
    key = FlowKey(
        src_addr=_u32_pair_to_addr(sa, sh),
        dst_addr=_u32_pair_to_addr(da, dh),
        protocol=proto,
        src_port=sport,
        dst_port=dport,
    )
    return FlowRecord(
        key=key,
        packets=packets,
        octets=octets,
        first_ts=first_ts,
        last_ts=last_ts,
        tos=tos,
        min_ttl=min_ttl,
        max_ttl=max_ttl,
    )


def write_nf8(records: list[FlowRecord], path: str) -> int:
    """Write flow records to a binary .nf8 file.

    Returns the number of records written.
    """
    with open(path, "wb") as f:
        f.write(struct.pack(NF8_HEADER_FMT, NF8_MAGIC, 1, len(records)))
        for rec in records:
            f.write(encode_record(rec))
    return len(records)


def read_nf8(path: str) -> list[FlowRecord]:
    """Read flow records from a .nf8 file."""
    with open(path, "rb") as f:
        hdr = f.read(NF8_HEADER_SIZE)
        if len(hdr) < NF8_HEADER_SIZE:
            raise ValueError("Truncated NF8 header")
        magic, _version, count = struct.unpack(NF8_HEADER_FMT, hdr)
        if magic != NF8_MAGIC:
            raise ValueError(f"Bad NF8 magic: 0x{magic:08X}")
        records: list[FlowRecord] = []
        for _ in range(count):
            chunk = f.read(BINARY_RECORD_SIZE)
            if len(chunk) < BINARY_RECORD_SIZE:
                break
            records.append(decode_record(chunk))
    return records


# ---------------------------------------------------------------------------
# Collector stats
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class CollectorStats:
    """Aggregate collector statistics."""

    active_flows: int = 0
    total_observed: int = 0
    total_exported: int = 0
    total_octets: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "active_flows": self.active_flows,
            "total_observed": self.total_observed,
            "total_exported": self.total_exported,
            "total_octets": self.total_octets,
        }


# ---------------------------------------------------------------------------
# Flow Collector
# ---------------------------------------------------------------------------

DEFAULT_ACTIVE_TIMEOUT = 120.0
DEFAULT_IDLE_TIMEOUT = 15.0


class FlowCollector:
    """NetFlow8 flow collector.

    Tracks active flows, exports them on idle/active timeout, and provides
    top-N analytics.

    Parameters
    ----------
    active_timeout
        Maximum lifetime of a flow in seconds before forced export.
    idle_timeout
        Seconds of inactivity before a flow is exported.
    clock
        Optional clock callable for testing (returns float seconds).
    """

    def __init__(
        self,
        *,
        active_timeout: float = DEFAULT_ACTIVE_TIMEOUT,
        idle_timeout: float = DEFAULT_IDLE_TIMEOUT,
        clock: object | None = None,
    ) -> None:
        self._active_timeout = active_timeout
        self._idle_timeout = idle_timeout
        self._clock = clock if clock is not None else time.monotonic
        self._flows: dict[FlowKey, _ActiveFlow] = {}
        self._exported: list[FlowRecord] = []
        self._total_observed: int = 0
        self._total_octets: int = 0

    # ---- observation ----

    def observe(
        self,
        packet: IPv8Packet,
        *,
        src_port: int = 0,
        dst_port: int = 0,
    ) -> FlowKey:
        """Record a packet observation.

        Creates a new flow entry or updates an existing one.
        Returns the flow key.
        """
        now: float = self._clock()  # type: ignore[operator]
        key = FlowKey(
            src_addr=packet.src,
            dst_addr=packet.dst,
            protocol=packet.protocol,
            src_port=src_port,
            dst_port=dst_port,
        )

        flow = self._flows.get(key)
        if flow is None:
            flow = _ActiveFlow(key=key)
            self._flows[key] = flow

        flow.update(packet, now)
        self._total_observed += 1
        self._total_octets += len(packet.payload) + 28
        return key

    # ---- export ----

    def export_expired(self) -> list[FlowRecord]:
        """Export all expired flows (idle or active timeout).

        Expired flows are removed from the active table and returned
        as FlowRecord objects.
        """
        now: float = self._clock()  # type: ignore[operator]
        expired_keys: list[FlowKey] = []
        for key, flow in self._flows.items():
            idle = now - flow.last_ts
            active = now - flow.first_ts
            if idle > self._idle_timeout or active > self._active_timeout:
                expired_keys.append(key)

        records: list[FlowRecord] = []
        for key in expired_keys:
            flow = self._flows.pop(key)
            rec = flow.to_record()
            records.append(rec)
            self._exported.append(rec)
        return records

    def export_all(self) -> list[FlowRecord]:
        """Force-export all active flows."""
        records: list[FlowRecord] = []
        for flow in self._flows.values():
            rec = flow.to_record()
            records.append(rec)
            self._exported.append(rec)
        self._flows.clear()
        return records

    # ---- analytics ----

    def top_talkers(self, n: int = 10) -> list[FlowRecord]:
        """Return top-N flows by packet count (active + exported)."""
        all_recs = [f.to_record() for f in self._flows.values()]
        all_recs.extend(self._exported)
        all_recs.sort(key=lambda r: r.packets, reverse=True)
        return all_recs[:n]

    def top_by_octets(self, n: int = 10) -> list[FlowRecord]:
        """Return top-N flows by byte count."""
        all_recs = [f.to_record() for f in self._flows.values()]
        all_recs.extend(self._exported)
        all_recs.sort(key=lambda r: r.octets, reverse=True)
        return all_recs[:n]

    def protocol_breakdown(self) -> dict[int, int]:
        """Return packet count per protocol number."""
        counts: dict[int, int] = {}
        for flow in self._flows.values():
            counts[flow.key.protocol] = counts.get(flow.key.protocol, 0) + flow.packets
        for rec in self._exported:
            counts[rec.key.protocol] = counts.get(rec.key.protocol, 0) + rec.packets
        return counts

    # ---- queries ----

    def get_flow(self, key: FlowKey) -> FlowRecord | None:
        """Look up an active flow by key."""
        flow = self._flows.get(key)
        return flow.to_record() if flow else None

    @property
    def active_count(self) -> int:
        return len(self._flows)

    @property
    def exported_count(self) -> int:
        return len(self._exported)

    @property
    def exported_records(self) -> list[FlowRecord]:
        return list(self._exported)

    def stats(self) -> CollectorStats:
        return CollectorStats(
            active_flows=len(self._flows),
            total_observed=self._total_observed,
            total_exported=len(self._exported),
            total_octets=self._total_octets,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "stats": self.stats().to_dict(),
            "active_flows": [f.to_record().to_dict() for f in self._flows.values()],
            "exported_flows": [r.to_dict() for r in self._exported],
        }

    def clear(self) -> None:
        """Reset all state."""
        self._flows.clear()
        self._exported.clear()
        self._total_observed = 0
        self._total_octets = 0
