# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""XLATE8 north-south traffic flow per Section 1.4.

North-south traffic (internal ↔ external) requires:
  1. DNS8 lookup to resolve external destination
  2. XLATE8 state table entry created from DNS8 result
  3. No DNS lookup = no XLATE8 entry = packet blocked
  4. Zone Server translates internal 127.x address ↔ external ASN address
  5. Ingress filtering validates returning traffic

Flow (egress — internal device reaching external service):
  Device 127.x.y.z → DNS8 lookup → XLATE8 entry created →
  Zone Server rewrites src to external ASN address →
  packet exits via border router

Flow (ingress — response returning):
  External source → border router → ingress filter →
  Zone Server XLATE8 reverse lookup → rewrite dst to 127.x.y.z →
  deliver to device

This module ties together: dns_a8, companions.XLATE8Table,
packet, address, security, netlog8.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from ipv8lab.address import IPv8Address
from ipv8lab.companions import XLATE8Entry, XLATE8Table
from ipv8lab.dns_a8 import A8Record
from ipv8lab.netlog8 import NetLog8Client, NetLog8Facility
from ipv8lab.packet import IPv8Packet


# ---------------------------------------------------------------------------
# DNS8 resolver (simplified mock for XLATE8 flow)
# ---------------------------------------------------------------------------

class DNS8Resolver:
    """Mock DNS8 resolver that returns A8 records."""

    def __init__(self) -> None:
        self._records: dict[str, A8Record] = {}

    def add_record(self, record: A8Record) -> None:
        self._records[record.name] = record

    def resolve(self, name: str) -> A8Record | None:
        return self._records.get(name)

    @property
    def size(self) -> int:
        return len(self._records)


# ---------------------------------------------------------------------------
# XLATE8 flow event tracking
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class FlowEvent:
    """A single event in the north-south traffic flow."""

    step: str
    direction: str        # "egress" or "ingress"
    success: bool
    detail: str = ""


# ---------------------------------------------------------------------------
# XLATE8 north-south flow engine
# ---------------------------------------------------------------------------

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
        self._clock = clock if clock is not None else time.monotonic
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

    # ---- Egress flow ----

    def dns_lookup(self, hostname: str) -> A8Record | None:
        """Step 1: DNS8 lookup for external destination."""
        record = self._dns.resolve(hostname)
        if record is None:
            self._logger.warning(
                NetLog8Facility.DNS8,
                f"DNS8 lookup failed: {hostname}",
            )
            self._record("dns_lookup", "egress", False, f"NXDOMAIN: {hostname}")
            return None

        self._logger.info(
            NetLog8Facility.DNS8,
            f"DNS8 resolved: {hostname} → {record.address}",
        )
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
        """Step 2: Create XLATE8 state table entry from DNS8 result."""
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
            self._logger.warning(
                NetLog8Facility.GENERAL,
                "XLATE8 entry rejected (dns_validated=False)",
            )
            self._record("xlate_create", "egress", False, "dns_validated=False")
        return ok

    def translate_egress(
        self,
        packet: IPv8Packet,
        internal_port: int = 0,
    ) -> IPv8Packet | None:
        """Step 3: Translate internal source to external address.

        Rewrites packet src from 127.x internal to external ASN address.
        Returns None if no XLATE8 entry found (= blocked).
        """
        entry = self._xlate.lookup_internal(str(packet.src), internal_port)
        if entry is None:
            self._logger.sec_alert(
                NetLog8Facility.GENERAL,
                f"No XLATE8 entry for {packet.src}:{internal_port} — blocked",
            )
            self._record(
                "translate_egress", "egress", False,
                f"no entry for {packet.src}:{internal_port}",
            )
            return None

        # Rewrite source to external address
        external_src = IPv8Address.parse(entry.external_address)
        translated = IPv8Packet(
            src=external_src,
            dst=packet.dst,
            payload=packet.payload,
        )
        self._logger.info(
            NetLog8Facility.GENERAL,
            f"Egress translate: {packet.src} → {external_src}",
        )
        self._record(
            "translate_egress", "egress", True,
            f"{packet.src} → {external_src}",
        )
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
        """Full egress flow: DNS8 → XLATE8 → translate.

        Returns translated packet or None if blocked.
        """
        # 1. DNS lookup
        record = self.dns_lookup(hostname)
        if record is None:
            return None

        # 2. Create XLATE8 entry
        ok = self.create_xlate_entry(
            internal_addr=internal_addr,
            external_addr=record.address,
            protocol=protocol,
            internal_port=internal_port,
            external_port=external_port,
        )
        if not ok:
            return None

        # 3. Build packet and translate
        pkt = IPv8Packet(src=internal_addr, dst=record.address, payload=payload)
        return self.translate_egress(pkt, internal_port)

    # ---- Ingress flow ----

    def translate_ingress(
        self,
        packet: IPv8Packet,
        external_port: int = 0,
    ) -> IPv8Packet | None:
        """Reverse-translate ingress packet: external dst → internal dst.

        Looks up XLATE8 entry by matching the packet's destination
        against known external addresses.
        """
        # Reverse lookup: find entry where external_address matches packet.dst
        dst_str = str(packet.dst)
        for entry in self._xlate.entries():
            if entry.external_address == dst_str and entry.external_port == external_port:
                internal_dst = IPv8Address.parse(entry.internal_address)
                translated = IPv8Packet(
                    src=packet.src,
                    dst=internal_dst,
                    payload=packet.payload,
                )
                self._logger.info(
                    NetLog8Facility.GENERAL,
                    f"Ingress translate: {packet.dst} → {internal_dst}",
                )
                self._record(
                    "translate_ingress", "ingress", True,
                    f"{packet.dst} → {internal_dst}",
                )
                return translated

        self._logger.sec_alert(
            NetLog8Facility.GENERAL,
            f"No XLATE8 reverse entry for {packet.dst}:{external_port} — blocked",
        )
        self._record(
            "translate_ingress", "ingress", False,
            f"no reverse entry for {packet.dst}:{external_port}",
        )
        return None

    def ingress_flow(
        self,
        external_src: IPv8Address,
        external_dst: IPv8Address,
        payload: bytes = b"response",
        external_port: int = 0,
    ) -> IPv8Packet | None:
        """Full ingress flow: reverse-translate external → internal.

        Returns translated packet or None if no matching XLATE8 entry.
        """
        pkt = IPv8Packet(src=external_src, dst=external_dst, payload=payload)
        return self.translate_ingress(pkt, external_port)

    # ---- Round-trip ----

    def round_trip(
        self,
        hostname: str,
        internal_addr: IPv8Address,
        response_payload: bytes = b"response",
        protocol: int = 6,
        internal_port: int = 0,
        external_port: int = 0,
    ) -> tuple[IPv8Packet | None, IPv8Packet | None]:
        """Full round-trip: egress then simulated ingress response.

        Returns (egress_packet, ingress_packet). Either may be None
        if translation fails.
        """
        # Egress
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

        # Simulate response from external (swap src/dst)
        ingress_pkt = self.ingress_flow(
            external_src=egress_pkt.dst,
            external_dst=egress_pkt.src,  # the translated external src
            payload=response_payload,
            external_port=external_port,
        )
        return egress_pkt, ingress_pkt

    # ---- Introspection ----

    @property
    def all_events_passed(self) -> bool:
        return all(e.success for e in self._events)

    @property
    def failed_events(self) -> list[FlowEvent]:
        return [e for e in self._events if not e.success]
