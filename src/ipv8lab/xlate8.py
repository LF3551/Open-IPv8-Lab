# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""XLATE8 unified subsystem.

Provides a single state-table substrate and five selectable translation
modes per the spec §XLATE8 Terminology:

1. **NATIVE**        — native IPv8 forwarding (no address rewrite)
2. **FOUR_TO_EIGHT** — IPv4-only host → IPv8 boundary translation
3. **EIGHT_TO_FOUR** — IPv8 → IPv4-only destination translation
4. **NAPT_RN**       — 8-to-8 NAPT between RN namespaces
5. **ENCAP**         — IPv8-over-IPv4 encapsulation for IPv4-only transit

Even/odd `.254`/`.253` load-balancing (``EvenOddLB``) is a deployment
pattern combining **NATIVE + ENCAP**, not a separate subsystem — use
:class:`EvenOddLB` directly from this module.

The :class:`NorthSouthFlow` orchestrator (DNS8 → XLATE8 → egress/ingress)
lives in this module and uses the shared state table
internally.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import NamedTuple

from ipv8lab.address import IPv8Address
from ipv8lab.companions import XLATE8Entry, XLATE8Table
from ipv8lab.packet import IPv8Packet


# ---------------------------------------------------------------------------
# Translation mode
# ---------------------------------------------------------------------------

class Xlate8Mode(IntEnum):
    """XLATE8 translation mode (spec §XLATE8 Terminology)."""

    NATIVE        = 1  # native IPv8 forwarding — no address rewrite
    FOUR_TO_EIGHT = 2  # IPv4-only host → IPv8 boundary
    EIGHT_TO_FOUR = 3  # IPv8 → IPv4-only destination
    NAPT_RN       = 4  # 8-to-8 NAPT between RN namespaces
    ENCAP         = 5  # IPv8-over-IPv4 encapsulation (IPv4-only transit)


# ---------------------------------------------------------------------------
# Translation result
# ---------------------------------------------------------------------------

class TranslationResult(NamedTuple):
    """Result of a single :meth:`Xlate8.translate` call."""

    success: bool
    packet: IPv8Packet | None
    mode: Xlate8Mode
    detail: str = ""


# ---------------------------------------------------------------------------
# Encap/decap helpers (mode ENCAP)
# ---------------------------------------------------------------------------

# Experimental IPv8-in-IPv4 IP protocol number (IANA-pending; use 253)
_PROTO_IPV8_IN_IPV4 = 253

# Minimal fake IPv4 header constants for encap framing
_IPV4_HDR_LEN = 20  # no options
_IPV4_VERSION_IHL = 0x45  # version=4, IHL=5


def _build_encap_frame(inner: bytes, src_ipv4: str, dst_ipv4: str) -> bytes:
    """Wrap IPv8 bytes in a minimal IPv4 header for transit.

    Uses IP protocol number 253 (experimental, IANA-pending).
    """
    src = _ipv4_to_int(src_ipv4)
    dst = _ipv4_to_int(dst_ipv4)
    total_len = _IPV4_HDR_LEN + len(inner)
    # Build header without checksum first, then compute
    hdr = struct.pack(
        "!BBHHHBBHII",
        _IPV4_VERSION_IHL,   # version + IHL
        0,                    # DSCP/ECN
        total_len,
        0,                    # identification
        0,                    # flags + frag offset
        64,                   # TTL
        _PROTO_IPV8_IN_IPV4,  # protocol
        0,                    # checksum placeholder
        src,
        dst,
    )
    checksum = _ipv4_checksum(hdr)
    hdr = hdr[:10] + struct.pack("!H", checksum) + hdr[12:]
    return hdr + inner


def _strip_encap_frame(frame: bytes) -> bytes | None:
    """Strip IPv4 encapsulation header.  Returns inner bytes or None on error."""
    if len(frame) < _IPV4_HDR_LEN:
        return None
    ihl = (frame[0] & 0x0F) * 4
    if frame[9] != _PROTO_IPV8_IN_IPV4:
        return None
    return frame[ihl:]


def _ipv4_to_int(addr: str) -> int:
    parts = addr.split(".")
    if len(parts) != 4:  # noqa: PLR2004
        msg = f"Invalid IPv4: {addr!r}"
        raise ValueError(msg)
    result = 0
    for p in parts:
        result = (result << 8) | int(p)
    return result


def _ipv4_checksum(data: bytes) -> int:
    s = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + (data[i + 1] if i + 1 < len(data) else 0)
        s += word
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


# ---------------------------------------------------------------------------
# Unified XLATE8 gateway
# ---------------------------------------------------------------------------

@dataclass
class Xlate8:
    """Unified XLATE8 gateway.

    A single :class:`~ipv8lab.companions.XLATE8Table` state substrate
    serves all five modes.  Instantiate one gateway per logical
    translation boundary (border router interface).

    Parameters
    ----------
    mode:
        Active translation mode.
    local_rn:
        The RN this gateway represents (used for NAPT_RN source
        rewriting and NATIVE passthrough validation).
    encap_src_ipv4 / encap_dst_ipv4:
        IPv4 tunnel endpoints used in ``ENCAP`` and ``FOUR_TO_EIGHT``
        modes.  Not required for other modes.
    """

    mode: Xlate8Mode = Xlate8Mode.NATIVE
    local_rn: int = 0
    encap_src_ipv4: str = "0.0.0.0"
    encap_dst_ipv4: str = "0.0.0.0"
    _table: XLATE8Table = field(default_factory=XLATE8Table, init=False)

    # ----------------------------------------------------------------
    # State table access
    # ----------------------------------------------------------------

    @property
    def table(self) -> XLATE8Table:
        """The shared state table."""
        return self._table

    def install(self, entry: XLATE8Entry) -> bool:
        """Install a translation entry.  Returns False if rejected."""
        return self._table.create_entry(entry)

    # ----------------------------------------------------------------
    # Core translate API
    # ----------------------------------------------------------------

    def translate(
        self,
        packet: IPv8Packet,
        src_port: int = 0,
        dst_port: int = 0,
    ) -> TranslationResult:
        """Translate *packet* according to :attr:`mode`.

        Returns a :class:`TranslationResult` with the (possibly rewritten)
        packet or ``None`` on failure/block.
        """
        if self.mode == Xlate8Mode.NATIVE:
            return self._mode_native(packet)
        if self.mode == Xlate8Mode.FOUR_TO_EIGHT:
            return self._mode_4to8(packet, src_port)
        if self.mode == Xlate8Mode.EIGHT_TO_FOUR:
            return self._mode_8to4(packet, src_port)
        if self.mode == Xlate8Mode.NAPT_RN:
            return self._mode_napt_rn(packet, src_port, dst_port)
        if self.mode == Xlate8Mode.ENCAP:
            return self._mode_encap(packet)
        return TranslationResult(False, None, self.mode, "unknown mode")

    def reverse_translate(
        self,
        packet: IPv8Packet,
        dst_port: int = 0,
    ) -> TranslationResult:
        """Reverse-translate (ingress direction)."""
        if self.mode == Xlate8Mode.NATIVE:
            return TranslationResult(True, packet, self.mode, "native passthrough")
        if self.mode in (Xlate8Mode.FOUR_TO_EIGHT, Xlate8Mode.NAPT_RN):
            return self._reverse_xlate(packet, dst_port)
        if self.mode == Xlate8Mode.EIGHT_TO_FOUR:
            return self._mode_8to4_reverse(packet, dst_port)
        if self.mode == Xlate8Mode.ENCAP:
            return self._mode_encap_decap(packet)
        return TranslationResult(False, None, self.mode, "unknown mode")

    # ----------------------------------------------------------------
    # Mode 1: NATIVE
    # ----------------------------------------------------------------

    def _mode_native(self, packet: IPv8Packet) -> TranslationResult:
        """Native IPv8 forwarding — no address rewrite."""
        return TranslationResult(True, packet, Xlate8Mode.NATIVE, "native passthrough")

    # ----------------------------------------------------------------
    # Mode 2: FOUR_TO_EIGHT
    # ----------------------------------------------------------------

    def _mode_4to8(self, packet: IPv8Packet, src_port: int) -> TranslationResult:
        """IPv4-only host → IPv8 boundary.

        Looks up state table entry; rewrites src to the external IPv8
        address bound for this IPv4 source.
        """
        entry = self._table.lookup_internal(str(packet.src), src_port)
        if entry is None:
            return TranslationResult(
                False, None, Xlate8Mode.FOUR_TO_EIGHT,
                f"no state entry for {packet.src}:{src_port}",
            )
        new_src = IPv8Address.parse(entry.external_address)
        translated = IPv8Packet(src=new_src, dst=packet.dst, payload=packet.payload)
        return TranslationResult(
            True, translated, Xlate8Mode.FOUR_TO_EIGHT,
            f"{packet.src} → {new_src}",
        )

    def _reverse_xlate(self, packet: IPv8Packet, dst_port: int) -> TranslationResult:
        """Common reverse lookup: external dst → internal dst."""
        dst_str = str(packet.dst)
        for entry in self._table.entries():
            if entry.external_address == dst_str and entry.external_port == dst_port:
                internal_dst = IPv8Address.parse(entry.internal_address)
                translated = IPv8Packet(
                    src=packet.src,
                    dst=internal_dst,
                    payload=packet.payload,
                )
                return TranslationResult(
                    True, translated, self.mode,
                    f"{packet.dst} → {internal_dst}",
                )
        return TranslationResult(
            False, None, self.mode,
            f"no reverse entry for {packet.dst}:{dst_port}",
        )

    # ----------------------------------------------------------------
    # Mode 3: EIGHT_TO_FOUR
    # ----------------------------------------------------------------

    def _mode_8to4(self, packet: IPv8Packet, src_port: int) -> TranslationResult:
        """IPv8 → IPv4-only destination.

        Rewrites dst to the mapped IPv4-compatible address and strips
        the RN component.  Implemented as a dst rewrite using state
        table; src is preserved.
        """
        entry = self._table.lookup_internal(str(packet.dst), src_port)
        if entry is None:
            # Destination not in state table — allow pass-through if
            # dst RN == 0 (already IPv4-compatible)
            if packet.dst.rn == 0:
                return TranslationResult(
                    True, packet, Xlate8Mode.EIGHT_TO_FOUR,
                    "dst already IPv4-compatible (RN=0)",
                )
            return TranslationResult(
                False, None, Xlate8Mode.EIGHT_TO_FOUR,
                f"no state entry for {packet.dst}:{src_port}",
            )
        new_dst = IPv8Address.parse(entry.external_address)
        translated = IPv8Packet(src=packet.src, dst=new_dst, payload=packet.payload)
        return TranslationResult(
            True, translated, Xlate8Mode.EIGHT_TO_FOUR,
            f"{packet.dst} → {new_dst}",
        )

    def _mode_8to4_reverse(self, packet: IPv8Packet, dst_port: int) -> TranslationResult:
        return self._reverse_xlate(packet, dst_port)

    # ----------------------------------------------------------------
    # Mode 4: NAPT_RN
    # ----------------------------------------------------------------

    def _mode_napt_rn(
        self,
        packet: IPv8Packet,
        src_port: int,
        dst_port: int,
    ) -> TranslationResult:
        """8-to-8 NAPT between RN namespaces.

        Rewrites src RN to :attr:`local_rn`, preserving LA.
        """
        if self.local_rn == 0:
            return TranslationResult(
                False, None, Xlate8Mode.NAPT_RN, "local_rn not configured",
            )
        entry = self._table.lookup_internal(str(packet.src), src_port)
        if entry is None:
            # Auto-create a passthrough entry using the local_rn rewrite
            la_str = packet.src.la_str
            new_src_str = f"{self.local_rn}-{la_str}"
            try:
                new_src = IPv8Address.parse(new_src_str)
            except Exception:  # noqa: BLE001
                return TranslationResult(
                    False, None, Xlate8Mode.NAPT_RN,
                    f"cannot rewrite src to RN {self.local_rn}",
                )
            translated = IPv8Packet(src=new_src, dst=packet.dst, payload=packet.payload)
            return TranslationResult(
                True, translated, Xlate8Mode.NAPT_RN,
                f"{packet.src} → {new_src} (RN rewrite)",
            )
        # Use state table mapping
        new_src = IPv8Address.parse(entry.external_address)
        translated = IPv8Packet(src=new_src, dst=packet.dst, payload=packet.payload)
        return TranslationResult(
            True, translated, Xlate8Mode.NAPT_RN,
            f"{packet.src} → {new_src}",
        )

    # ----------------------------------------------------------------
    # Mode 5: ENCAP
    # ----------------------------------------------------------------

    def _mode_encap(self, packet: IPv8Packet) -> TranslationResult:
        """IPv8-over-IPv4 encapsulation for IPv4-only transit.

        Wraps the IPv8 packet in a minimal IPv4 header using
        IP protocol 253 (experimental).
        """
        if self.encap_src_ipv4 == "0.0.0.0" or self.encap_dst_ipv4 == "0.0.0.0":
            return TranslationResult(
                False, None, Xlate8Mode.ENCAP,
                "encap_src_ipv4/encap_dst_ipv4 not configured",
            )
        raw = _build_encap_frame(
            packet.to_bytes(),
            self.encap_src_ipv4,
            self.encap_dst_ipv4,
        )
        # Store as a passthrough IPv8 packet carrying the encap bytes as payload
        encap_pkt = IPv8Packet(src=packet.src, dst=packet.dst, payload=raw)
        return TranslationResult(
            True, encap_pkt, Xlate8Mode.ENCAP,
            f"encap {len(raw)} bytes ({self.encap_src_ipv4} → {self.encap_dst_ipv4})",
        )

    def _mode_encap_decap(self, packet: IPv8Packet) -> TranslationResult:
        """Strip IPv4 encap wrapper on ingress."""
        inner = _strip_encap_frame(packet.payload)
        if inner is None:
            return TranslationResult(
                False, None, Xlate8Mode.ENCAP, "not a valid encap frame",
            )
        try:
            inner_pkt = IPv8Packet.from_bytes(inner)
        except Exception as exc:  # noqa: BLE001
            return TranslationResult(False, None, Xlate8Mode.ENCAP, str(exc))
        return TranslationResult(True, inner_pkt, Xlate8Mode.ENCAP, "decap ok")

    # ----------------------------------------------------------------
    # Introspection
    # ----------------------------------------------------------------

    @property
    def entry_count(self) -> int:
        return self._table.size

    def to_dict(self) -> dict[str, object]:
        return {
            "mode": self.mode.name,
            "local_rn": self.local_rn,
            "entries": self._table.size,
        }


# ===========================================================================
# DNS8 resolver
# ===========================================================================

class DNS8Resolver:
    """Mock DNS8 resolver that returns A8 records."""

    def __init__(self) -> None:
        self._records: dict[str, "A8Record"] = {}

    def add_record(self, record: "A8Record") -> None:
        self._records[record.name] = record

    def resolve(self, name: str) -> "A8Record | None":
        return self._records.get(name)

    @property
    def size(self) -> int:
        return len(self._records)


# ===========================================================================
# Flow event
# ===========================================================================

@dataclass(frozen=True, slots=True)
class FlowEvent:
    """A single event in the north-south traffic flow."""

    step: str
    direction: str        # "egress" or "ingress"
    success: bool
    detail: str = ""


# ===========================================================================
# NorthSouthFlow
# ===========================================================================

import time as _time

from ipv8lab.dns_a8 import A8Record
from ipv8lab.netlog8 import NetLog8Client, NetLog8Facility


class NorthSouthFlow:
    """XLATE8 north-south traffic flow engine.

    Orchestrates the full egress/ingress lifecycle:
    DNS8 → XLATE8 → translation → routing → ingress filter.
    """

    def __init__(
        self,
        zone_prefix: str = "127.1.0.0",
        external_asn: int = 64496,
        clock: object | None = None,
    ) -> None:
        self._zone_prefix = zone_prefix
        self._external_asn = external_asn
        self._dns = DNS8Resolver()
        self._xlate = XLATE8Table()
        self._logger = NetLog8Client(source="xlate8-flow", endpoint="netlog")
        self._events: list[FlowEvent] = []
        self._clock = clock if clock is not None else _time.monotonic
        if clock is not None:
            self._logger._clock = clock

    @property
    def dns(self) -> DNS8Resolver:
        return self._dns

    @property
    def xlate_table(self) -> XLATE8Table:
        return self._xlate

    @property
    def events(self) -> list[FlowEvent]:
        return list(self._events)

    @property
    def zone_prefix(self) -> str:
        return self._zone_prefix

    @property
    def external_asn(self) -> int:
        return self._external_asn

    def _record(self, step: str, direction: str, success: bool, detail: str = "") -> FlowEvent:
        evt = FlowEvent(step=step, direction=direction, success=success, detail=detail)
        self._events.append(evt)
        return evt

    # ---- Egress ----

    def dns_lookup(self, hostname: str) -> "A8Record | None":
        record = self._dns.resolve(hostname)
        if record is None:
            self._logger.warning(NetLog8Facility.DNS8, f"DNS8 lookup failed: {hostname}")
            self._record("dns_lookup", "egress", False, f"NXDOMAIN: {hostname}")
            return None
        self._logger.info(NetLog8Facility.DNS8, f"DNS8 resolved: {hostname} → {record.address}")
        self._record("dns_lookup", "egress", True, f"{hostname} → {record.address}")
        return record

    def create_xlate_entry(
        self,
        internal_addr: IPv8Address,
        external_addr: IPv8Address,
        protocol: int = 6,
        internal_port: int = 0,
        external_port: int = 0,
    ) -> bool:
        now: float = self._clock()  # type: ignore[operator]
        entry = XLATE8Entry(
            internal_address=str(internal_addr),
            external_address=str(external_addr),
            protocol=protocol,
            internal_port=internal_port,
            external_port=external_port,
            dns_validated=True,
            created_at=now,
        )
        ok = self._xlate.create_entry(entry)
        if ok:
            self._logger.info(
                NetLog8Facility.GENERAL,
                f"XLATE8 entry: {internal_addr}:{internal_port} ↔ {external_addr}:{external_port}",
            )
            self._record(
                "xlate_create", "egress", True,
                f"{internal_addr}:{internal_port} ↔ {external_addr}:{external_port}",
            )
        else:
            self._logger.warning(NetLog8Facility.GENERAL, "XLATE8 entry rejected (dns_validated=False)")
            self._record("xlate_create", "egress", False, "dns_validated=False")
        return ok

    def translate_egress(self, packet: IPv8Packet, internal_port: int = 0) -> IPv8Packet | None:
        entry = self._xlate.lookup_internal(str(packet.src), internal_port)
        if entry is None:
            self._logger.sec_alert(
                NetLog8Facility.GENERAL,
                f"No XLATE8 entry for {packet.src}:{internal_port} — blocked",
            )
            self._record("translate_egress", "egress", False, f"no entry for {packet.src}:{internal_port}")
            return None
        external_src = IPv8Address.parse(entry.external_address)
        translated = IPv8Packet(src=external_src, dst=packet.dst, payload=packet.payload)
        self._logger.info(NetLog8Facility.GENERAL, f"Egress translate: {packet.src} → {external_src}")
        self._record("translate_egress", "egress", True, f"{packet.src} → {external_src}")
        return translated

    def egress_flow(
        self,
        hostname: str,
        internal_addr: IPv8Address,
        payload: bytes = b"egress",
        protocol: int = 6,
        internal_port: int = 0,
        external_port: int = 0,
    ) -> IPv8Packet | None:
        record = self.dns_lookup(hostname)
        if record is None:
            return None
        ok = self.create_xlate_entry(
            internal_addr=internal_addr,
            external_addr=record.address,
            protocol=protocol,
            internal_port=internal_port,
            external_port=external_port,
        )
        if not ok:
            return None
        pkt = IPv8Packet(src=internal_addr, dst=record.address, payload=payload)
        return self.translate_egress(pkt, internal_port)

    # ---- Ingress ----

    def translate_ingress(self, packet: IPv8Packet, external_port: int = 0) -> IPv8Packet | None:
        dst_str = str(packet.dst)
        for entry in self._xlate.entries():
            if entry.external_address == dst_str and entry.external_port == external_port:
                internal_dst = IPv8Address.parse(entry.internal_address)
                translated = IPv8Packet(src=packet.src, dst=internal_dst, payload=packet.payload)
                self._logger.info(
                    NetLog8Facility.GENERAL, f"Ingress translate: {packet.dst} → {internal_dst}",
                )
                self._record("translate_ingress", "ingress", True, f"{packet.dst} → {internal_dst}")
                return translated
        self._logger.sec_alert(
            NetLog8Facility.GENERAL,
            f"No XLATE8 reverse entry for {packet.dst}:{external_port} — blocked",
        )
        self._record("translate_ingress", "ingress", False, f"no reverse entry for {packet.dst}:{external_port}")
        return None

    def ingress_flow(
        self,
        external_src: IPv8Address,
        external_dst: IPv8Address,
        payload: bytes = b"response",
        external_port: int = 0,
    ) -> IPv8Packet | None:
        pkt = IPv8Packet(src=external_src, dst=external_dst, payload=payload)
        return self.translate_ingress(pkt, external_port)

    def round_trip(
        self,
        hostname: str,
        internal_addr: IPv8Address,
        response_payload: bytes = b"response",
        protocol: int = 6,
        internal_port: int = 0,
        external_port: int = 0,
    ) -> tuple[IPv8Packet | None, IPv8Packet | None]:
        egress_pkt = self.egress_flow(
            hostname=hostname,
            internal_addr=internal_addr,
            payload=b"request",
            protocol=protocol,
            internal_port=internal_port,
            external_port=external_port,
        )
        if egress_pkt is None:
            return None, None
        ingress_pkt = self.ingress_flow(
            external_src=egress_pkt.dst,
            external_dst=egress_pkt.src,
            payload=response_payload,
            external_port=external_port,
        )
        return egress_pkt, ingress_pkt

    @property
    def all_events_passed(self) -> bool:
        return all(e.success for e in self._events)

    @property
    def failed_events(self) -> list[FlowEvent]:
        return [e for e in self._events if not e.success]


# ===========================================================================
# Even/Odd Load Balancing
# ===========================================================================

from enum import Enum as _Enum


class Parity(str, _Enum):
    EVEN = "even"
    ODD = "odd"


def address_parity(addr: IPv8Address) -> Parity:
    """Determine parity of the host address (last octet)."""
    return Parity.EVEN if addr.host_part[3] % 2 == 0 else Parity.ODD


@dataclass(frozen=True, slots=True)
class A8Pair:
    """An even/odd A8 address pair for a single host."""

    even: IPv8Address
    odd: IPv8Address

    def to_dict(self) -> dict[str, str]:
        return {"even": self.even.full_notation, "odd": self.odd.full_notation}


def make_a8_pair(asn: int, host_base: str) -> A8Pair:
    """Create an even/odd A8 pair from *asn* and 3-octet *host_base* like ``'10.0.0'``."""
    parts = host_base.rstrip(".").split(".")
    if len(parts) != 3:  # noqa: PLR2004
        msg = f"host_base must be 3 octets (e.g. '10.0.0'), got {host_base!r}"
        raise ValueError(msg)
    prefix = ".".join(parts)
    even_addr = IPv8Address.parse(f"{asn}.{prefix}.2")
    odd_addr = IPv8Address.parse(f"{asn}.{prefix}.3")
    return A8Pair(even=even_addr, odd=odd_addr)


class LBStrategy(str, _Enum):
    PASSTHROUGH = "passthrough"
    ROUND_ROBIN = "round_robin"
    EVEN_ONLY = "even_only"
    ODD_ONLY = "odd_only"


@dataclass(frozen=True, slots=True)
class LBConnection:
    """One load-balanced connection."""

    client_addr: str
    client_port: int
    selected: IPv8Address
    parity: Parity
    seq: int


@dataclass
class EvenOddLB:
    """XLATE8 Even/Odd load balancer.

    Even/odd load balancing is a deployment pattern of NATIVE + ENCAP modes,
    not a separate subsystem.
    """

    pair: A8Pair
    strategy: LBStrategy = LBStrategy.ROUND_ROBIN
    _counter: int = field(default=0, init=False)
    _connections: list[LBConnection] = field(default_factory=list, init=False)

    def select(self, client_addr: str = "0.0.0.0", client_port: int = 0) -> LBConnection:
        if self.strategy == LBStrategy.EVEN_ONLY:
            chosen = self.pair.even
        elif self.strategy == LBStrategy.ODD_ONLY:
            chosen = self.pair.odd
        else:
            chosen = self.pair.even if self._counter % 2 == 0 else self.pair.odd
        parity = address_parity(chosen)
        conn = LBConnection(
            client_addr=client_addr,
            client_port=client_port,
            selected=chosen,
            parity=parity,
            seq=self._counter,
        )
        self._connections.append(conn)
        self._counter += 1
        return conn

    def distribute(self, client_addr: str, count: int) -> list[LBConnection]:
        return [self.select(client_addr=client_addr, client_port=10000 + i) for i in range(count)]

    @property
    def connections(self) -> list[LBConnection]:
        return list(self._connections)

    @property
    def stats(self) -> dict[str, int]:
        even_n = sum(1 for c in self._connections if c.parity == Parity.EVEN)
        odd_n = len(self._connections) - even_n
        return {"total": len(self._connections), "even": even_n, "odd": odd_n}

    def reset(self) -> None:
        self._connections.clear()
        self._counter = 0

    def summary(self) -> dict[str, object]:
        return {
            "pair": self.pair.to_dict(),
            "strategy": self.strategy.value,
            "stats": self.stats,
        }
