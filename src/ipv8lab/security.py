# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Border router security checks per draft-thain-ipv8-00 Section 18.

Implements ingress/egress filtering rules for IPv8 border routers:
- 18.1: ASN prefix spoofing — source r.r.r.r must match peer ASN
- 18.2: Internal zone (127.x.x.x) must not appear on WAN
- 18.3: RINE (100.x.x.x) must not appear in eBGP8
- 18.4: Interior link (222.x.x.x host) must not be routed externally
- 18.6: Cross-ASN multicast protocol prefixes must be filtered at border
- 18.7: /16 minimum prefix enforcement
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from ipv8lab.packet import IPv8Packet


class Severity(str, Enum):
    """Alert severity level."""

    INFO = "INFO"
    WARNING = "WARNING"
    SEC_ALERT = "SEC-ALERT"


@dataclass(frozen=True, slots=True)
class SecurityViolation:
    """A single security violation detected by border filtering."""

    section: str
    severity: Severity
    message: str


@dataclass(slots=True)
class IngressFilter:
    """Ingress filter for an IPv8 border router.

    Validates incoming packets against Section 18 rules.
    """

    peer_asn: int
    """The ASN of the BGP8 peer on this interface."""

    is_external: bool = True
    """True if this is a WAN/external interface."""

    def check(self, packet: IPv8Packet) -> list[SecurityViolation]:
        """Check a packet against all ingress rules. Returns violations."""
        violations: list[SecurityViolation] = []
        src = packet.src
        dst = packet.dst

        # 18.1: ASN prefix spoofing
        if self.is_external and src.asn != self.peer_asn and not src.is_ipv4_compatible():
            violations.append(SecurityViolation(
                section="18.1",
                severity=Severity.SEC_ALERT,
                message=(
                    f"ASN prefix spoofing: source ASN {src.asn} "
                    f"does not match peer ASN {self.peer_asn}"
                ),
            ))

        # 18.2: Internal zone prefix
        if self.is_external:
            if src.is_internal_zone():
                violations.append(SecurityViolation(
                    section="18.2",
                    severity=Severity.SEC_ALERT,
                    message=(
                        f"Internal zone source {src.full_notation} "
                        "on external interface"
                    ),
                ))
            if dst.is_internal_zone():
                violations.append(SecurityViolation(
                    section="18.2",
                    severity=Severity.SEC_ALERT,
                    message=(
                        f"Internal zone destination {dst.full_notation} "
                        "on external interface"
                    ),
                ))

        # 18.3: RINE prefix
        if self.is_external:
            if src.is_rine_prefix():
                violations.append(SecurityViolation(
                    section="18.3",
                    severity=Severity.SEC_ALERT,
                    message=(
                        f"RINE source {src.full_notation} "
                        "on non-peering interface"
                    ),
                ))
            if dst.is_rine_prefix():
                violations.append(SecurityViolation(
                    section="18.3",
                    severity=Severity.SEC_ALERT,
                    message=(
                        f"RINE destination {dst.full_notation} "
                        "on non-peering interface"
                    ),
                ))

        # 18.4: Interior link convention (222.x.x.x in host part)
        if self.is_external:
            if src.is_interior_link():
                violations.append(SecurityViolation(
                    section="18.4",
                    severity=Severity.SEC_ALERT,
                    message=(
                        f"Interior link source {src.full_notation} "
                        "on external interface"
                    ),
                ))
            if dst.is_interior_link():
                violations.append(SecurityViolation(
                    section="18.4",
                    severity=Severity.SEC_ALERT,
                    message=(
                        f"Interior link destination {dst.full_notation} "
                        "on external interface"
                    ),
                ))

        # 18.6: Cross-ASN multicast protocol filtering
        _filtered_prefixes = {
            (255, 255, 0, 1),  # OSPF8
            (255, 255, 0, 2),  # BGP8
            (255, 255, 0, 3),  # EIGRP
            (255, 255, 0, 4),  # RIP
            (255, 255, 0, 5),  # IS-IS8
        }
        if self.is_external and dst.routing_prefix in _filtered_prefixes:
            violations.append(SecurityViolation(
                section="18.6",
                severity=Severity.SEC_ALERT,
                message=(
                    f"Cross-ASN multicast protocol prefix "
                    f"{dst.full_notation} must be filtered at border"
                ),
            ))

        return violations


def check_bgp8_prefix_length(prefix_str: str) -> SecurityViolation | None:
    """Check /16 minimum injectable prefix rule (Section 18.7).

    prefix_str: a CIDR-like notation e.g. "0.0.251.240/16"
    Returns a violation if prefix is more specific than /16.
    """
    parts = prefix_str.split("/")
    if len(parts) != 2:
        return None
    try:
        length = int(parts[1])
    except ValueError:
        return None
    if length > 16:
        return SecurityViolation(
            section="18.7",
            severity=Severity.SEC_ALERT,
            message=(
                f"Prefix {prefix_str} is more specific than /16. "
                "MUST NOT be advertised across AS boundaries."
            ),
        )
    return None
