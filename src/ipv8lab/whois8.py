# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""WHOIS8 mock resolver per draft-thain-ipv8-02.

WHOIS8 validates that ASN holders legitimately own their advertised
prefixes. BGP8 route advertisements are validated against WHOIS8
before installation in the routing table. A route that cannot be
validated is not installed.

This module provides a mock resolver for testing and simulation.

Key behaviours from the spec:
- Section 1.4: destination ASN validated against WHOIS8 registry
- Section 8.3: eBGP8 routes validated before acceptance
- Section 18.7: /16 minimum prefix enforcement
- Prefix hijacking prevention: requires both RIR entry + valid WHOIS8 record
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto

from ipv8lab.address import IPv8Address, asn_to_prefix


class ValidationStatus(Enum):
    """WHOIS8 validation result status."""

    VALID = auto()
    UNKNOWN_ASN = auto()
    PREFIX_MISMATCH = auto()
    EXPIRED = auto()
    RESERVED_RANGE = auto()
    PREFIX_TOO_SPECIFIC = auto()


@dataclass(frozen=True, slots=True)
class WHOIS8Record:
    """A WHOIS8 registry record for an ASN."""

    asn: int
    holder: str
    country: str = ""
    prefix_min: int = 16  # minimum prefix length the ASN may advertise
    active: bool = True

    @property
    def prefix_str(self) -> str:
        """The r.r.r.r prefix for this ASN."""
        p = asn_to_prefix(self.asn)
        return ".".join(str(o) for o in p)


@dataclass(frozen=True, slots=True)
class ValidationResult:
    """Result of a WHOIS8 validation query."""

    status: ValidationStatus
    asn: int
    record: WHOIS8Record | None = None
    reason: str = ""

    @property
    def is_valid(self) -> bool:
        return self.status == ValidationStatus.VALID


# Reserved ASN ranges that MUST NOT be in public WHOIS8
_INTERNAL_ZONE_ASN_MIN = 2130706432  # 127.0.0.0 as uint32
_INTERNAL_ZONE_ASN_MAX = 2147483647  # 127.255.255.255 as uint32
_RINE_ASN_MIN = 1677721600           # 100.0.0.0 as uint32
_RINE_ASN_MAX = 1694498815           # 100.255.255.255 as uint32


def _is_reserved_asn(asn: int) -> str | None:
    """Check if ASN falls in a reserved range. Returns reason or None."""
    if _INTERNAL_ZONE_ASN_MIN <= asn <= _INTERNAL_ZONE_ASN_MAX:
        return "ASN in internal zone range (127.0.0.0/8)"
    if _RINE_ASN_MIN <= asn <= _RINE_ASN_MAX:
        return "ASN in RINE peering range (100.0.0.0/8)"
    if asn == 65534:
        return "ASN 65534 reserved for private peering"
    if asn == 65533:
        return "ASN 65533 reserved for documentation"
    return None


@dataclass
class WHOIS8Resolver:
    """Mock WHOIS8 resolver for route validation.

    Maintains a registry of ASN → record mappings and validates
    route advertisements against it.
    """

    _registry: dict[int, WHOIS8Record] = field(default_factory=dict)

    def register(self, record: WHOIS8Record) -> None:
        """Register an ASN in the WHOIS8 registry."""
        reserved = _is_reserved_asn(record.asn)
        if reserved:
            msg = f"Cannot register reserved ASN {record.asn}: {reserved}"
            raise ValueError(msg)
        self._registry[record.asn] = record

    def unregister(self, asn: int) -> None:
        """Remove an ASN from the registry."""
        if asn not in self._registry:
            msg = f"ASN {asn} not in registry"
            raise KeyError(msg)
        del self._registry[asn]

    def lookup(self, asn: int) -> WHOIS8Record | None:
        """Look up an ASN record."""
        return self._registry.get(asn)

    def validate_route(self, asn: int, prefix_length: int = 8) -> ValidationResult:
        """Validate a BGP8 route advertisement.

        Checks:
        1. ASN is not in a reserved range
        2. ASN is registered in WHOIS8
        3. ASN record is active (not expired)
        4. Prefix is not more specific than /16 (Section 18.7)
        """
        reserved = _is_reserved_asn(asn)
        if reserved:
            return ValidationResult(
                status=ValidationStatus.RESERVED_RANGE,
                asn=asn,
                reason=reserved,
            )

        record = self._registry.get(asn)
        if record is None:
            return ValidationResult(
                status=ValidationStatus.UNKNOWN_ASN,
                asn=asn,
                reason=f"ASN {asn} not found in WHOIS8 registry",
            )

        if not record.active:
            return ValidationResult(
                status=ValidationStatus.EXPIRED,
                asn=asn,
                record=record,
                reason=f"ASN {asn} record is inactive/expired",
            )

        if prefix_length > 16:
            return ValidationResult(
                status=ValidationStatus.PREFIX_TOO_SPECIFIC,
                asn=asn,
                record=record,
                reason=f"Prefix /{prefix_length} more specific than /16 minimum",
            )

        return ValidationResult(
            status=ValidationStatus.VALID,
            asn=asn,
            record=record,
        )

    def validate_destination(self, address: IPv8Address) -> ValidationResult:
        """Validate a destination address against WHOIS8.

        Per Section 1.4: destination ASN is validated against the
        WHOIS8 registry — if the destination prefix is not registered
        as an active route, the packet is dropped.
        """
        if address.is_ipv4_compatible():
            return ValidationResult(
                status=ValidationStatus.VALID,
                asn=0,
                reason="IPv4-compatible address, bypasses WHOIS8",
            )

        asn = address.asn

        reserved = _is_reserved_asn(asn)
        if reserved:
            return ValidationResult(
                status=ValidationStatus.RESERVED_RANGE,
                asn=asn,
                reason=reserved,
            )

        record = self._registry.get(asn)
        if record is None:
            return ValidationResult(
                status=ValidationStatus.UNKNOWN_ASN,
                asn=asn,
                reason=f"Destination ASN {asn} not in WHOIS8 registry",
            )

        if not record.active:
            return ValidationResult(
                status=ValidationStatus.EXPIRED,
                asn=asn,
                record=record,
                reason=f"Destination ASN {asn} record expired",
            )

        return ValidationResult(
            status=ValidationStatus.VALID,
            asn=asn,
            record=record,
        )

    def list_asns(self) -> list[int]:
        """List all registered ASNs."""
        return sorted(self._registry.keys())

    def __len__(self) -> int:
        return len(self._registry)
