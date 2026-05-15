# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Inter-Company Interop and Two-XLATE8 model per draft-thain-ipv8-02 Sections 4.6–4.7.

Section 4.6 — Inter-Company Interop Prefix (127.127.0.0):
  Reserved DMZ address space for two organisations to interconnect
  without exposing internal zone addressing.

Section 4.7 — Two-XLATE8 Interop Model:
  Company A (127.1.0.0.x) ↔ XLATE8-A ↔ 127.127.0.0.x ↔ XLATE8-B ↔ Company B (127.2.0.0.x)
  Neither company sees the other's internal addresses.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

INTEROP_PREFIX = "127.127.0.0"
"""The reserved inter-company interoperability DMZ prefix (Section 4.6)."""


# ---------------------------------------------------------------------------
# Translation entry
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class InteropEntry:
    """A single XLATE8 interop translation mapping."""

    internal_address: str    # e.g. 127.1.0.0.10.0.0.5
    interop_address: str     # e.g. 127.127.0.0.10.0.0.5
    protocol: int = 6        # TCP
    internal_port: int = 0
    interop_port: int = 0
    created_at: float = 0.0


# ---------------------------------------------------------------------------
# Per-company XLATE8 engine
# ---------------------------------------------------------------------------

class InteropXLATE8Engine:
    """XLATE8 engine for one side of the inter-company interop (Section 4.6).

    Translates between an organisation's internal zone addresses and
    the shared 127.127.0.0 interop prefix.
    """

    def __init__(self, company_name: str, internal_prefix: str) -> None:
        self.company_name = company_name
        self.internal_prefix = internal_prefix  # e.g. "127.1.0.0"
        self._table: dict[str, InteropEntry] = {}
        self._reverse: dict[str, InteropEntry] = {}

    def expose_service(
        self,
        internal_address: str,
        interop_host: str,
        *,
        protocol: int = 6,
        internal_port: int = 443,
        interop_port: int = 443,
    ) -> InteropEntry:
        """Expose an internal service on the interop DMZ.

        ``internal_address`` — full internal addr (e.g. 127.1.0.0.10.0.0.5)
        ``interop_host`` — host part in the interop space (e.g. 10.0.0.5)
        """
        interop_addr = f"{INTEROP_PREFIX}.{interop_host}"
        entry = InteropEntry(
            internal_address=internal_address,
            interop_address=interop_addr,
            protocol=protocol,
            internal_port=internal_port,
            interop_port=interop_port,
            created_at=time.time(),
        )
        self._table[internal_address] = entry
        self._reverse[interop_addr] = entry
        return entry

    def translate_outbound(self, internal_address: str) -> str | None:
        """Translate internal → interop (outbound toward partner).

        Returns the interop address or None if no mapping exists.
        """
        entry = self._table.get(internal_address)
        if entry is None:
            return None
        return entry.interop_address

    def translate_inbound(self, interop_address: str) -> str | None:
        """Translate interop → internal (inbound from partner).

        Returns the internal address or None if no mapping exists.
        """
        entry = self._reverse.get(interop_address)
        if entry is None:
            return None
        return entry.internal_address

    def entries(self) -> list[InteropEntry]:
        return list(self._table.values())

    @property
    def size(self) -> int:
        return len(self._table)


# ---------------------------------------------------------------------------
# Interop flow event
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class InteropFlowEvent:
    """A single step in an inter-company flow."""

    step: str
    src: str
    dst: str
    note: str = ""


# ---------------------------------------------------------------------------
# Two-XLATE8 bridge (Section 4.7)
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class TwoXLATE8Bridge:
    """Two-XLATE8 Interop Model connecting two companies (Section 4.7).

    Company A  ↔  XLATE8-A  ↔  127.127.0.0  ↔  XLATE8-B  ↔  Company B

    Properties:
    - Company A never sees Company B's internal addresses.
    - Company B never sees Company A's internal addresses.
    - Each company controls exactly what it exposes.
    - No address overlap possible. No NAT complexity.
    """

    engine_a: InteropXLATE8Engine
    engine_b: InteropXLATE8Engine
    events: list[InteropFlowEvent] = field(default_factory=list)

    def send(
        self,
        from_company: str,
        src_internal: str,
        dst_interop_host: str,
    ) -> list[InteropFlowEvent]:
        """Simulate a packet from one company to the other through the bridge.

        ``from_company`` — "A" or "B"
        ``src_internal`` — sender's internal address
        ``dst_interop_host`` — destination host part in 127.127.0.0 space
        """
        dst_interop = f"{INTEROP_PREFIX}.{dst_interop_host}"
        flow: list[InteropFlowEvent] = []

        if from_company.upper() == "A":
            sender, receiver = self.engine_a, self.engine_b
        else:
            sender, receiver = self.engine_b, self.engine_a

        # Step 1: sender XLATE8 translates src internal → interop
        src_interop = sender.translate_outbound(src_internal)
        if src_interop is None:
            flow.append(InteropFlowEvent(
                step="blocked",
                src=src_internal,
                dst=dst_interop,
                note=f"No interop mapping for {src_internal} on {sender.company_name}",
            ))
            self.events.extend(flow)
            return flow

        flow.append(InteropFlowEvent(
            step="xlate8_outbound",
            src=src_interop,
            dst=dst_interop,
            note=f"{sender.company_name}: {src_internal} → {src_interop}",
        ))

        # Step 2: packet traverses 127.127.0.0 DMZ
        flow.append(InteropFlowEvent(
            step="interop_dmz",
            src=src_interop,
            dst=dst_interop,
            note=f"Transit on {INTEROP_PREFIX} DMZ",
        ))

        # Step 3: receiver XLATE8 translates dst interop → internal
        dst_internal = receiver.translate_inbound(dst_interop)
        if dst_internal is None:
            flow.append(InteropFlowEvent(
                step="blocked",
                src=src_interop,
                dst=dst_interop,
                note=f"No inbound mapping for {dst_interop} on {receiver.company_name}",
            ))
            self.events.extend(flow)
            return flow

        flow.append(InteropFlowEvent(
            step="xlate8_inbound",
            src=src_interop,
            dst=dst_internal,
            note=f"{receiver.company_name}: {dst_interop} → {dst_internal}",
        ))

        # Step 4: delivered
        flow.append(InteropFlowEvent(
            step="delivered",
            src=src_interop,
            dst=dst_internal,
            note="Packet delivered to destination internal address",
        ))

        self.events.extend(flow)
        return flow

    def clear_events(self) -> int:
        n = len(self.events)
        self.events.clear()
        return n


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def is_interop_prefix(address: str) -> bool:
    """Check if an address is in the 127.127.0.0 interop space."""
    parts = address.split(".")
    if len(parts) == 8:
        return parts[0] == "127" and parts[1] == "127" and parts[2] == "0" and parts[3] == "0"
    return False


def validate_interop_isolation(bridge: TwoXLATE8Bridge) -> list[str]:
    """Verify that neither company can see the other's internal addresses.

    Returns a list of violations (empty = OK).
    """
    violations: list[str] = []

    a_internals = {e.internal_address for e in bridge.engine_a.entries()}
    b_internals = {e.internal_address for e in bridge.engine_b.entries()}

    # Check A's entries don't reference B's internals
    for entry in bridge.engine_a.entries():
        if entry.internal_address in b_internals:
            violations.append(
                f"Company {bridge.engine_a.company_name} exposes "
                f"Company {bridge.engine_b.company_name}'s address: {entry.internal_address}"
            )

    # Check B's entries don't reference A's internals
    for entry in bridge.engine_b.entries():
        if entry.internal_address in a_internals:
            violations.append(
                f"Company {bridge.engine_b.company_name} exposes "
                f"Company {bridge.engine_a.company_name}'s address: {entry.internal_address}"
            )

    return violations


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------

def make_interop_bridge(
    company_a_name: str = "Company-A",
    company_a_prefix: str = "127.1.0.0",
    company_b_name: str = "Company-B",
    company_b_prefix: str = "127.2.0.0",
) -> TwoXLATE8Bridge:
    """Create a Two-XLATE8 bridge between two companies."""
    return TwoXLATE8Bridge(
        engine_a=InteropXLATE8Engine(company_a_name, company_a_prefix),
        engine_b=InteropXLATE8Engine(company_b_name, company_b_prefix),
    )
