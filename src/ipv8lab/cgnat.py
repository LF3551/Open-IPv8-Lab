# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""CGNAT Behaviour simulation per draft-thain-ipv8-02 Section 15.

Key rules:
- IPv8-aware CGNAT MUST NOT modify the r.r.r.r field during translation.
- Only the n.n.n.n field is subject to NAT translation.
- CGNAT operators without an ASN MUST use r.r.r.r = 0.0.0.0.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from ipv8lab.address import IPv8Address


# ---------------------------------------------------------------------------
# Translation result
# ---------------------------------------------------------------------------

class CGNATViolation(str, Enum):
    NONE = "none"
    PREFIX_MODIFIED = "prefix_modified"
    NO_ASN_NONZERO_PREFIX = "no_asn_nonzero_prefix"


@dataclass(frozen=True, slots=True)
class TranslationBinding:
    """One NAT binding: inside ↔ outside mapping."""

    inside: IPv8Address
    outside: IPv8Address
    port_inside: int
    port_outside: int


@dataclass(frozen=True, slots=True)
class TranslationResult:
    """Result of a CGNAT translation attempt."""

    original: IPv8Address
    translated: IPv8Address
    violation: CGNATViolation
    note: str = ""


# ---------------------------------------------------------------------------
# CGNAT Engine
# ---------------------------------------------------------------------------

@dataclass
class CGNATEngine:
    """IPv8-aware CGNAT engine per Section 15.

    Parameters:
        operator_asn: The operator's ASN.  0 means no ASN assigned.
        pool_start:   First n.n.n.n in the outside NAT pool.
        pool_end:     Last n.n.n.n in the outside NAT pool.
    """

    operator_asn: int = 0
    pool_start: str = "198.51.100.1"
    pool_end: str = "198.51.100.254"
    _next_port: int = field(default=10000, init=False)
    _pool_idx: int = field(default=0, init=False)
    _bindings: list[TranslationBinding] = field(default_factory=list, init=False)

    # -- pool management -----------------------------------------------------

    @property
    def operator_prefix(self) -> tuple[int, int, int, int]:
        """The r.r.r.r prefix this CGNAT preserves (0.0.0.0 if no ASN)."""
        if self.operator_asn == 0:
            return (0, 0, 0, 0)
        v = self.operator_asn
        return ((v >> 24) & 0xFF, (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF)

    def _next_outside_addr(self) -> str:
        """Pick the next address from the pool (round-robin)."""
        start_parts = [int(o) for o in self.pool_start.split(".")]
        end_parts = [int(o) for o in self.pool_end.split(".")]
        start_val = (start_parts[0] << 24) | (start_parts[1] << 16) | (start_parts[2] << 8) | start_parts[3]
        end_val = (end_parts[0] << 24) | (end_parts[1] << 16) | (end_parts[2] << 8) | end_parts[3]
        pool_size = end_val - start_val + 1
        chosen = start_val + (self._pool_idx % pool_size)
        self._pool_idx += 1
        return f"{(chosen >> 24) & 0xFF}.{(chosen >> 16) & 0xFF}.{(chosen >> 8) & 0xFF}.{chosen & 0xFF}"

    def _alloc_port(self) -> int:
        port = self._next_port
        self._next_port += 1
        if self._next_port > 65535:
            self._next_port = 10000
        return port

    # -- translation ---------------------------------------------------------

    def translate(
        self,
        addr: IPv8Address,
        src_port: int = 0,
    ) -> TranslationResult:
        """Translate *addr* through this CGNAT.

        Rules:
        - r.r.r.r is ALWAYS preserved (MUST NOT be modified).
        - Only n.n.n.n is translated to the outside pool.
        - If operator has no ASN, r.r.r.r MUST be 0.0.0.0.
        """
        # Rule: operators without ASN must use 0.0.0.0
        if self.operator_asn == 0 and addr.routing_prefix != (0, 0, 0, 0):
            return TranslationResult(
                original=addr,
                translated=addr,
                violation=CGNATViolation.NO_ASN_NONZERO_PREFIX,
                note="CGNAT operator without ASN received non-zero r.r.r.r — MUST use 0.0.0.0",
            )

        # Translate n.n.n.n only — r.r.r.r preserved
        outside_host = self._next_outside_addr()
        outside_port = self._alloc_port()

        translated = IPv8Address.parse(
            f"{addr.prefix_str}.{outside_host}"
        )

        binding = TranslationBinding(
            inside=addr,
            outside=translated,
            port_inside=src_port,
            port_outside=outside_port,
        )
        self._bindings.append(binding)

        return TranslationResult(
            original=addr,
            translated=translated,
            violation=CGNATViolation.NONE,
        )

    def reverse_translate(self, addr: IPv8Address) -> IPv8Address | None:
        """Find the inside address for an outside-translated address."""
        for b in reversed(self._bindings):
            if b.outside == addr:
                return b.inside
        return None

    # -- validation ----------------------------------------------------------

    def validate_translation(
        self,
        original: IPv8Address,
        translated: IPv8Address,
    ) -> CGNATViolation:
        """Validate that a translation preserved r.r.r.r."""
        if original.routing_prefix != translated.routing_prefix:
            return CGNATViolation.PREFIX_MODIFIED
        if self.operator_asn == 0 and translated.routing_prefix != (0, 0, 0, 0):
            return CGNATViolation.NO_ASN_NONZERO_PREFIX
        return CGNATViolation.NONE

    # -- inspection ----------------------------------------------------------

    @property
    def bindings(self) -> list[TranslationBinding]:
        return list(self._bindings)

    def flush(self) -> int:
        """Remove all bindings. Returns count removed."""
        n = len(self._bindings)
        self._bindings.clear()
        self._pool_idx = 0
        self._next_port = 10000
        return n

    def summary(self) -> dict[str, object]:
        return {
            "operator_asn": self.operator_asn,
            "prefix": ".".join(str(o) for o in self.operator_prefix),
            "pool": f"{self.pool_start}-{self.pool_end}",
            "active_bindings": len(self._bindings),
        }
