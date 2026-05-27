# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""IPv8 address parsing, conversion, and validation.

Canonical textual form per draft-thain-ipv8 §3.5 is the hyphenated
locator ``<RN>-<LA>``:

* leading RN octet == 0 (low ASNs) → RN rendered as an unsigned integer
  (``64500-192.0.2.1``)
* leading RN octet != 0 → RN rendered as dotted quad
  (``127.10.60.10-10.0.0.1``)

Legacy notations ``r.r.r.r.n.n.n.n`` (full 8-octet) and ``ASN.n.n.n.n``
(legacy dot-ASN) remain accepted as input. The emit/str/repr default is
the hyphenated canonical form.

The module-level flag :data:`ASN_SIMPLIFICATION` controls integer-RN
rendering. When ``False``, the RN portion is always emitted as a dotted
quad regardless of leading octet (spec §3.5). Wire/JSON encoding is
unaffected by this flag.
"""

from __future__ import annotations

from dataclasses import dataclass

from ipv8lab.errors import InvalidAddressError, InvalidASNError, InvalidOctetError

MAX_ASN = 4_294_967_295 # 2^32 - 1

#: When True (default), RNs with leading octet 0 are rendered as integers
#: in :pyattr:`IPv8Address.canonical`. Set False to force dotted-quad RN.
ASN_SIMPLIFICATION = True


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
    return prefix_to_asn(octets) # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class IPv8Address:
    """Immutable IPv8 address with a 4-octet routing prefix and a 4-octet host part."""

    routing_prefix: tuple[int, int, int, int]
    host_part: tuple[int, int, int, int]

    # --- derived properties ---------------------------------------------------

    @property
    def asn(self) -> int:
        return prefix_to_asn(self.routing_prefix)

    #: Spec alias for :pyattr:`asn` — Routing Number.
    @property
    def rn(self) -> int:
        return self.asn

    #: Spec alias for :pyattr:`routing_prefix` — RN as 4 octets.
    @property
    def rn_octets(self) -> tuple[int, int, int, int]:
        return self.routing_prefix

    #: Spec alias for :pyattr:`host_part` — Local Address (LA).
    @property
    def la_octets(self) -> tuple[int, int, int, int]:
        return self.host_part

    @property
    def prefix_str(self) -> str:
        return ".".join(str(o) for o in self.routing_prefix)

    @property
    def host_str(self) -> str:
        return ".".join(str(o) for o in self.host_part)

    @property
    def la_str(self) -> str:
        """Spec alias for :pyattr:`host_str` — LA dotted quad."""
        return self.host_str

    @property
    def rn_str(self) -> str:
        """RN as dotted quad (always 4 octets, regardless of leading value)."""
        return self.prefix_str

    @property
    def full_notation(self) -> str:
        """Full 8-octet dotted notation: ``r.r.r.r.n.n.n.n`` (legacy)."""
        return f"{self.prefix_str}.{self.host_str}"

    @property
    def dotted_notation(self) -> str:
        """Spec alias for :pyattr:`full_notation`."""
        return self.full_notation

    @property
    def asn_notation(self) -> str:
        """Legacy ASN dot notation: ``ASN.n.n.n.n``."""
        return f"{self.asn}.{self.host_str}"

    @property
    def canonical(self) -> str:
        """Spec canonical hyphenated form ``<RN>-<LA>``.

        Uses integer RN when the leading RN octet is 0 and
        :data:`ASN_SIMPLIFICATION` is True; otherwise dotted-quad RN.
        """
        if ASN_SIMPLIFICATION and self.routing_prefix[0] == 0:
            return f"{self.asn}-{self.host_str}"
        return f"{self.prefix_str}-{self.host_str}"

    # --- address class classification (Section 4) ----------------------------

    def is_ipv4_compatible(self) -> bool:
        """True if routing prefix is 0.0.0.0 (Section 3.3)."""
        return self.routing_prefix == (0, 0, 0, 0)

    def is_internal_zone(self) -> bool:
        """True if r.r.r.r is in 127.0.0.0/8 (Section 3.5)."""
        return self.routing_prefix[0] == 127

    def is_interop_prefix(self) -> bool:
        """True if r.r.r.r is 127.127.0.0 — inter-company interop DMZ (Section 3.6)."""
        return self.routing_prefix == (127, 127, 0, 0)

    def is_rine_prefix(self) -> bool:
        """True if r.r.r.r is in 100.0.0.0/8 — RINE peering fabric (Section 3.9)."""
        return self.routing_prefix[0] == 100

    def is_interior_link(self) -> bool:
        """True if n.n.n.n is in 222.0.0.0/8 — interior link convention (Section 3.10)."""
        return self.host_part[0] == 222

    def is_broadcast(self) -> bool:
        """True if r.r.r.r is ff.ff.ff.ff (Section 12)."""
        return self.routing_prefix == (255, 255, 255, 255)

    def is_multicast(self) -> bool:
        """True if r.r.r.r is in ff.ff.00.00/16 — cross-ASN multicast (Section 10.2)."""
        return self.routing_prefix[0] == 255 and self.routing_prefix[1] == 255

    def is_intra_asn_multicast(self) -> bool:
        """True if IPv4-compat and n.n.n.n in 224.0.0.0/4 (Section 10.1)."""
        return self.is_ipv4_compatible() and 224 <= self.host_part[0] <= 239

    def is_unicast(self) -> bool:
        """True if address is a regular ASN unicast address (Section 4)."""
        return (
            not self.is_ipv4_compatible()
            and not self.is_internal_zone()
            and not self.is_rine_prefix()
            and not self.is_broadcast()
            and not self.is_multicast()
        )

    def is_private_peering_asn(self) -> bool:
        """True if ASN 65534 — private inter-company BGP8 peering (Section 3.8)."""
        return self.asn == 65534

    def is_documentation_asn(self) -> bool:
        """True if ASN 65533 — documentation and testing (Section 3.8)."""
        return self.asn == 65533

    # --- spec reserved-block table (leading-RN-octet categories) ------------

    def is_super_scalar(self) -> bool:
        """True if leading RN octet is 1–32 — super-scalar RN pool."""
        return 1 <= self.routing_prefix[0] <= 32

    def is_rir_sub_rn(self) -> bool:
        """True if leading RN octet is 110–119 — RIR-delegated sub-RN range."""
        return 110 <= self.routing_prefix[0] <= 119

    @property
    def rir(self) -> str | None:
        """RIR name for RIR sub-RN addresses, or None if not applicable.

        Mapping: 110=ARIN, 111=RIPE, 112=APNIC, 113=LACNIC, 114=AFRINIC.
        115–119 reserved for future RIR assignments.
        """
        _map = {110: "ARIN", 111: "RIPE", 112: "APNIC", 113: "LACNIC", 114: "AFRINIC"}
        return _map.get(self.routing_prefix[0])

    def is_cellular_carrier(self) -> bool:
        """True if leading RN octet is 128–130 — cellular carrier RN range."""
        return 128 <= self.routing_prefix[0] <= 130

    def is_iana_reserved(self) -> bool:
        """True if leading RN octet falls in a gap reserved by IANA.

        Gaps: 33–99, 101–109, 120–126, 131–221, 223–254.
        (0=IPv4-compat pool, 100=RINE, 127=internal zone,
         222=interior link, 255=broadcast/multicast anchor — handled elsewhere.)
        """
        o = self.routing_prefix[0]
        return (
            33 <= o <= 99
            or 101 <= o <= 109
            or 120 <= o <= 126
            or 131 <= o <= 221
            or 223 <= o <= 254
        )

    def is_interop_prefix(self) -> bool:
        """True if RN is 127.127.0.0 — legacy inter-company interop DMZ.

        .. deprecated::
            The 127.127.0.0/16 Inter-Company Interop Prefix has been removed
            from the spec. Use the two-XLATE8 model instead. This method is
            retained for backwards compatibility and will be removed in a
            future release.
        """
        import warnings
        warnings.warn(
            "is_interop_prefix() is deprecated: the 127.127.0.0 Inter-Company "
            "Interop Prefix has been removed from the spec. "
            "Use the two-XLATE8 model (interop.py) instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.routing_prefix == (127, 127, 0, 0)

    @property
    def address_class(self) -> str:
        """Return the address class name per Section 4."""
        if self.is_broadcast():
            return "broadcast"
        if self.is_multicast():
            return "cross-asn-multicast"
        if self.is_intra_asn_multicast():
            return "intra-asn-multicast"
        if self.is_ipv4_compatible():
            return "ipv4-compatible"
        if self.is_internal_zone():
            return "internal-zone"
        if self.is_rine_prefix():
            return "rine-peering"
        return "asn-unicast"

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
            routing_prefix=tuple(octets[:4]), # type: ignore[arg-type]
            host_part=tuple(octets[4:]), # type: ignore[arg-type]
        )

    # --- parsing --------------------------------------------------------------

    @classmethod
    def parse(cls, text: str) -> "IPv8Address":
        """Parse an IPv8 address from a string.

        Supported input formats (spec draft-thain-ipv8 §3.5):

        * Canonical hyphenated: ``<RN>-<LA>``
          (``64496-192.0.2.1`` or ``127.10.60.10-10.0.0.1``)
        * Legacy full 8-octet: ``r.r.r.r.n.n.n.n``
        * Legacy dot-ASN: ``ASN.n.n.n.n``

        Emit/`str` always returns the hyphenated canonical form.
        """
        text = text.strip()
        if "-" in text:
            return cls._parse_hyphenated(text)
        parts = text.split(".")
        if len(parts) == 8:
            return cls._parse_full(parts)
        if len(parts) == 5:
            return cls._parse_asn_notation(parts)
        raise InvalidAddressError(
            "Expected hyphenated ``<RN>-<LA>``, 5-part ASN notation, or "
            f"8-part full notation, got {len(parts)} dot-parts: {text!r}"
        )

    @classmethod
    def _parse_hyphenated(cls, text: str) -> "IPv8Address":
        if text.count("-") != 1:
            raise InvalidAddressError(
                f"Hyphenated locator must contain exactly one '-': {text!r}"
            )
        rn_str, la_str = text.split("-", 1)
        rn_str = rn_str.strip()
        la_str = la_str.strip()
        if not rn_str or not la_str:
            raise InvalidAddressError(
                f"Empty RN or LA component in hyphenated locator: {text!r}"
            )
        # RN part: integer or dotted quad
        if "." in rn_str:
            rn_parts = rn_str.split(".")
            if len(rn_parts) != 4:
                raise InvalidAddressError(
                    f"RN dotted quad must have 4 octets, got {len(rn_parts)}: {rn_str!r}"
                )
            try:
                rn_octets = tuple(int(p) for p in rn_parts)
            except ValueError as exc:
                raise InvalidAddressError(f"Non-integer RN octet: {exc}") from exc
            for i, o in enumerate(rn_octets):
                validate_octet(o, label=f"RN octet {i}")
        else:
            try:
                rn_int = int(rn_str)
            except ValueError as exc:
                raise InvalidAddressError(f"Invalid RN integer: {exc}") from exc
            if not 0 <= rn_int <= MAX_ASN:
                raise InvalidASNError(f"RN must be 0-{MAX_ASN}, got {rn_int}")
            rn_octets = asn_to_prefix(rn_int)
        # LA part: dotted quad
        la_parts = la_str.split(".")
        if len(la_parts) != 4:
            raise InvalidAddressError(
                f"LA must be a 4-octet dotted quad, got {len(la_parts)} parts: {la_str!r}"
            )
        try:
            la_octets = tuple(int(p) for p in la_parts)
        except ValueError as exc:
            raise InvalidAddressError(f"Non-integer LA octet: {exc}") from exc
        for i, o in enumerate(la_octets):
            validate_octet(o, label=f"LA octet {i}")
        return cls(
            routing_prefix=rn_octets, # type: ignore[arg-type]
            host_part=la_octets, # type: ignore[arg-type]
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
            routing_prefix=tuple(octets[:4]), # type: ignore[arg-type]
            host_part=tuple(octets[4:]), # type: ignore[arg-type]
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
        return cls(routing_prefix=prefix, host_part=host) # type: ignore[arg-type]

    # --- dunder ---------------------------------------------------------------

    def __str__(self) -> str:
        return self.canonical

    def __repr__(self) -> str:
        return f"IPv8Address({self.canonical})"
