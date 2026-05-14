# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""IPv8 address parsing, conversion, and validation."""

from __future__ import annotations

from dataclasses import dataclass

from ipv8lab.errors import InvalidAddressError, InvalidASNError, InvalidOctetError

MAX_ASN = 4_294_967_295  # 2^32 - 1


def validate_octet(value: int, *, label: str = "octet") -> int:
    """Validate that *value* is in the 0-255 range."""
    if not 0 <= value <= 255:
        raise InvalidOctetError(f"{label} must be 0-255, got {value}")
    return value


def asn_to_prefix(asn: int) -> tuple[int, int, int, int]:
    """Convert a 32-bit ASN to a 4-octet routing prefix tuple."""
    if not 0 <= asn <= MAX_ASN:
        raise InvalidASNError(f"ASN must be 0-{MAX_ASN}, got {asn}")
    return (
        (asn >> 24) & 0xFF,
        (asn >> 16) & 0xFF,
        (asn >> 8) & 0xFF,
        asn & 0xFF,
    )


def prefix_to_asn(prefix: tuple[int, int, int, int]) -> int:
    """Convert a 4-octet routing prefix tuple to a 32-bit ASN."""
    for i, o in enumerate(prefix):
        validate_octet(o, label=f"prefix octet {i}")
    return (prefix[0] << 24) | (prefix[1] << 16) | (prefix[2] << 8) | prefix[3]


def asn_to_prefix_str(asn: int) -> str:
    """Return the dotted string form of the routing prefix for *asn*."""
    return ".".join(str(o) for o in asn_to_prefix(asn))


def prefix_str_to_asn(prefix_str: str) -> int:
    """Parse a dotted prefix string and return the ASN."""
    parts = prefix_str.split(".")
    if len(parts) != 4:
        raise InvalidAddressError(f"Routing prefix must have 4 octets, got {len(parts)}")
    octets = tuple(int(p) for p in parts)
    return prefix_to_asn(octets)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class IPv8Address:
    """Immutable IPv8 address with a 4-octet routing prefix and a 4-octet host part."""

    routing_prefix: tuple[int, int, int, int]
    host_part: tuple[int, int, int, int]

    # --- derived properties ---------------------------------------------------

    @property
    def asn(self) -> int:
        return prefix_to_asn(self.routing_prefix)

    @property
    def prefix_str(self) -> str:
        return ".".join(str(o) for o in self.routing_prefix)

    @property
    def host_str(self) -> str:
        return ".".join(str(o) for o in self.host_part)

    @property
    def full_notation(self) -> str:
        """Full 8-octet dotted notation: r.r.r.r.n.n.n.n"""
        return f"{self.prefix_str}.{self.host_str}"

    @property
    def asn_notation(self) -> str:
        """ASN dot notation: ASN.n.n.n.n"""
        return f"{self.asn}.{self.host_str}"

    def is_ipv4_compatible(self) -> bool:
        """True if routing prefix is 0.0.0.0."""
        return self.routing_prefix == (0, 0, 0, 0)

    def is_internal_zone(self) -> bool:
        """True if the first octet of the routing prefix is 127."""
        return self.routing_prefix[0] == 127

    def to_int(self) -> int:
        """Pack the full 8-octet address into a 64-bit integer."""
        octets = self.routing_prefix + self.host_part
        value = 0
        for o in octets:
            value = (value << 8) | o
        return value

    @staticmethod
    def from_int(value: int) -> "IPv8Address":
        """Unpack a 64-bit integer into an IPv8Address."""
        octets = []
        for _ in range(8):
            octets.append(value & 0xFF)
            value >>= 8
        octets.reverse()
        return IPv8Address(
            routing_prefix=tuple(octets[:4]),  # type: ignore[arg-type]
            host_part=tuple(octets[4:]),  # type: ignore[arg-type]
        )

    # --- parsing --------------------------------------------------------------

    @classmethod
    def parse(cls, text: str) -> "IPv8Address":
        """Parse an IPv8 address from a string.

        Supported formats:
        - Full 8-octet: ``r.r.r.r.n.n.n.n``
        - ASN dot notation: ``ASN.n.n.n.n``
        """
        parts = text.strip().split(".")
        if len(parts) == 8:
            return cls._parse_full(parts)
        if len(parts) == 5:
            return cls._parse_asn_notation(parts)
        raise InvalidAddressError(
            f"Expected 5 parts (ASN notation) or 8 parts (full notation), got {len(parts)}: {text}"
        )

    @classmethod
    def _parse_full(cls, parts: list[str]) -> "IPv8Address":
        try:
            octets = [int(p) for p in parts]
        except ValueError as exc:
            raise InvalidAddressError(f"Non-integer octet in address: {exc}") from exc
        for i, o in enumerate(octets):
            validate_octet(o, label=f"octet {i}")
        return cls(
            routing_prefix=tuple(octets[:4]),  # type: ignore[arg-type]
            host_part=tuple(octets[4:]),  # type: ignore[arg-type]
        )

    @classmethod
    def _parse_asn_notation(cls, parts: list[str]) -> "IPv8Address":
        try:
            asn = int(parts[0])
        except ValueError as exc:
            raise InvalidAddressError(f"Invalid ASN value: {exc}") from exc
        if not 0 <= asn <= MAX_ASN:
            raise InvalidASNError(f"ASN must be 0-{MAX_ASN}, got {asn}")
        prefix = asn_to_prefix(asn)
        try:
            host = tuple(int(p) for p in parts[1:])
        except ValueError as exc:
            raise InvalidAddressError(f"Non-integer octet in host part: {exc}") from exc
        for i, o in enumerate(host):
            validate_octet(o, label=f"host octet {i}")
        return cls(routing_prefix=prefix, host_part=host)  # type: ignore[arg-type]

    # --- dunder ---------------------------------------------------------------

    def __str__(self) -> str:
        return self.full_notation

    def __repr__(self) -> str:
        return f"IPv8Address({self.full_notation})"
