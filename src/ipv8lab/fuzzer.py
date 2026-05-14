# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Packet fuzzer for IPv8 protocol security testing.

Generates mutated IPv8 packets to test parser robustness,
security filters, and protocol handlers against malformed input.

Fuzzing strategies:
- Field mutation: flip bits, boundary values, random bytes
- Structural: truncation, extension, overlapping fragments
- Semantic: invalid versions, bad checksums, reserved addresses
- Replay: capture-based mutation of known-good packets

Usage::

    from ipv8lab.fuzzer import Fuzzer, FuzzStrategy, FuzzTarget

    fuzzer = Fuzzer(seed=42)
    results = fuzzer.run(count=100, target=FuzzTarget.PARSER)
    print(f"{results.crashes} crashes, {results.errors} errors")
"""

from __future__ import annotations

import os
import random
import struct
import zlib
from dataclasses import dataclass, field
from enum import Enum, IntEnum


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

HEADER_FORMAT = "!BBHHHBBHIIII"
HEADER_SIZE = 28
DEFAULT_VERSION_IHL = 0x87  # version=8, ihl=7
MAX_PACKET_SIZE = 65535
FRAG_UNIT = 8


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class FuzzStrategy(str, Enum):
    """Fuzzing strategy to apply."""

    BIT_FLIP = "bit_flip"
    BYTE_RANDOM = "byte_random"
    BOUNDARY = "boundary"
    TRUNCATE = "truncate"
    EXTEND = "extend"
    CHECKSUM = "checksum"
    FIELD_MUTATE = "field_mutate"
    FRAGMENT = "fragment"
    COMBINED = "combined"


class FuzzTarget(str, Enum):
    """Target subsystem for fuzzing."""

    PARSER = "parser"
    SECURITY = "security"
    FRAGMENT = "fragment"
    ROUTING = "routing"
    ALL = "all"


class FuzzSeverity(str, Enum):
    """Severity of a finding."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class MutationField(IntEnum):
    """Packet header fields that can be mutated."""

    VERSION_IHL = 0
    TOS = 1
    TOTAL_LENGTH = 2
    IDENTIFICATION = 3
    FLAGS_FRAG = 4
    TTL = 5
    PROTOCOL = 6
    CHECKSUM = 7
    SRC_ASN = 8
    SRC_HOST = 9
    DST_ASN = 10
    DST_HOST = 11


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class FuzzCase:
    """A single fuzz test case."""

    case_id: int
    strategy: FuzzStrategy
    raw_bytes: bytes
    description: str = ""
    mutations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "strategy": self.strategy.value,
            "raw_hex": self.raw_bytes.hex(),
            "size": len(self.raw_bytes),
            "description": self.description,
            "mutations": self.mutations,
        }


@dataclass(slots=True)
class FuzzFinding:
    """A finding from fuzzing — an anomalous response."""

    case_id: int
    severity: FuzzSeverity
    category: str
    description: str
    exception_type: str = ""
    exception_msg: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "severity": self.severity.value,
            "category": self.category,
            "description": self.description,
            "exception_type": self.exception_type,
            "exception_msg": self.exception_msg,
        }


@dataclass(slots=True)
class FuzzResult:
    """Summary results from a fuzzing run."""

    total_cases: int = 0
    crashes: int = 0
    errors: int = 0
    hangs: int = 0
    findings: list[FuzzFinding] = field(default_factory=list)
    cases: list[FuzzCase] = field(default_factory=list)

    @property
    def success_rate(self) -> float:
        if self.total_cases == 0:
            return 0.0
        return (self.total_cases - self.crashes) / self.total_cases

    def to_dict(self) -> dict[str, object]:
        return {
            "total_cases": self.total_cases,
            "crashes": self.crashes,
            "errors": self.errors,
            "hangs": self.hangs,
            "success_rate": round(self.success_rate, 4),
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass(slots=True)
class FuzzConfig:
    """Configuration for a fuzz run."""

    count: int = 100
    seed: int = 0
    strategies: list[FuzzStrategy] = field(default_factory=lambda: [FuzzStrategy.COMBINED])
    target: FuzzTarget = FuzzTarget.PARSER
    max_size: int = MAX_PACKET_SIZE
    min_size: int = 1

    def to_dict(self) -> dict[str, object]:
        return {
            "count": self.count,
            "seed": self.seed,
            "strategies": [s.value for s in self.strategies],
            "target": self.target.value,
            "max_size": self.max_size,
            "min_size": self.min_size,
        }


# ---------------------------------------------------------------------------
# Packet generation helpers
# ---------------------------------------------------------------------------


def _compute_checksum(header_bytes: bytes, payload: bytes) -> int:
    """Compute CRC32-based checksum (matching spec_packet)."""
    # Zero out checksum field (bytes 10-11) in header
    header_no_cksum = header_bytes[:10] + b"\x00\x00" + header_bytes[12:]
    return zlib.crc32(header_no_cksum + payload) & 0xFFFF


def build_valid_packet(
    src_asn: int = 64496,
    dst_asn: int = 64497,
    payload: bytes = b"",
    ttl: int = 64,
    protocol: int = 17,
    tos: int = 0,
    identification: int = 0,
) -> bytes:
    """Build a valid IPv8 packet with correct checksum."""
    total_length = HEADER_SIZE + len(payload)

    header = struct.pack(
        HEADER_FORMAT,
        DEFAULT_VERSION_IHL,  # version=8, ihl=7
        tos,
        total_length,
        identification,
        0,  # flags_frag
        ttl,
        protocol,
        0,  # checksum placeholder
        (src_asn >> 16) & 0xFFFFFFFF,  # src_asn_prefix
        (src_asn & 0xFFFF) << 16 | 0x0001,  # src_host
        (dst_asn >> 16) & 0xFFFFFFFF,  # dst_asn_prefix
        (dst_asn & 0xFFFF) << 16 | 0x0001,  # dst_host
    )

    cksum = _compute_checksum(header, payload)
    header = header[:10] + struct.pack("!H", cksum) + header[12:]
    return header + payload


# ---------------------------------------------------------------------------
# Mutation functions
# ---------------------------------------------------------------------------


def mutate_bit_flip(data: bytes, rng: random.Random) -> tuple[bytes, str]:
    """Flip a random bit in the packet."""
    if not data:
        return data, "empty"
    buf = bytearray(data)
    pos = rng.randint(0, len(buf) - 1)
    bit = rng.randint(0, 7)
    buf[pos] ^= 1 << bit
    return bytes(buf), f"bit_flip@{pos}:{bit}"


def mutate_byte_random(data: bytes, rng: random.Random) -> tuple[bytes, str]:
    """Replace random bytes with random values."""
    if not data:
        return data, "empty"
    buf = bytearray(data)
    count = rng.randint(1, max(1, len(buf) // 4))
    positions = []
    for _ in range(count):
        pos = rng.randint(0, len(buf) - 1)
        buf[pos] = rng.randint(0, 255)
        positions.append(pos)
    return bytes(buf), f"byte_random@[{','.join(map(str, positions[:5]))}]"


def mutate_boundary(data: bytes, rng: random.Random) -> tuple[bytes, str]:
    """Set fields to boundary values (0, max, off-by-one)."""
    if len(data) < HEADER_SIZE:
        return data, "too_short"
    buf = bytearray(data)
    boundaries_8 = [0, 1, 127, 128, 254, 255]
    boundaries_16 = [0, 1, 27, 28, 29, 255, 256, 65534, 65535]
    boundaries_32 = [0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF]

    field_choice = rng.randint(0, 11)
    desc = ""

    if field_choice == MutationField.VERSION_IHL:
        val = rng.choice(boundaries_8)
        buf[0] = val
        desc = f"version_ihl={val:#04x}"
    elif field_choice == MutationField.TOS:
        val = rng.choice(boundaries_8)
        buf[1] = val
        desc = f"tos={val}"
    elif field_choice == MutationField.TOTAL_LENGTH:
        val = rng.choice(boundaries_16)
        struct.pack_into("!H", buf, 2, val)
        desc = f"total_length={val}"
    elif field_choice == MutationField.IDENTIFICATION:
        val = rng.choice(boundaries_16)
        struct.pack_into("!H", buf, 4, val)
        desc = f"identification={val}"
    elif field_choice == MutationField.FLAGS_FRAG:
        val = rng.choice(boundaries_16)
        struct.pack_into("!H", buf, 6, val)
        desc = f"flags_frag={val:#06x}"
    elif field_choice == MutationField.TTL:
        val = rng.choice(boundaries_8)
        buf[8] = val
        desc = f"ttl={val}"
    elif field_choice == MutationField.PROTOCOL:
        val = rng.choice(boundaries_8)
        buf[9] = val
        desc = f"protocol={val}"
    elif field_choice == MutationField.CHECKSUM:
        val = rng.choice(boundaries_16)
        struct.pack_into("!H", buf, 10, val)
        desc = f"checksum={val:#06x}"
    elif field_choice >= MutationField.SRC_ASN:
        offset = 12 + (field_choice - MutationField.SRC_ASN) * 4
        val = rng.choice(boundaries_32)
        struct.pack_into("!I", buf, offset, val)
        desc = f"addr_field[{field_choice - 8}]={val:#010x}"

    return bytes(buf), f"boundary:{desc}"


def mutate_truncate(data: bytes, rng: random.Random) -> tuple[bytes, str]:
    """Truncate the packet at a random point."""
    if len(data) <= 1:
        return b"", "truncate@0"
    cut = rng.randint(1, len(data) - 1)
    return data[:cut], f"truncate@{cut}/{len(data)}"


def mutate_extend(data: bytes, rng: random.Random) -> tuple[bytes, str]:
    """Extend the packet with extra random bytes."""
    extra_len = rng.randint(1, 256)
    extra = bytes(rng.randint(0, 255) for _ in range(extra_len))
    return data + extra, f"extend+{extra_len}"


def mutate_checksum(data: bytes, rng: random.Random) -> tuple[bytes, str]:
    """Corrupt the checksum field specifically."""
    if len(data) < HEADER_SIZE:
        return data, "too_short"
    buf = bytearray(data)
    # Read current checksum and mutate it
    current = struct.unpack_from("!H", buf, 10)[0]
    new_val = (current + rng.randint(1, 65534)) & 0xFFFF
    struct.pack_into("!H", buf, 10, new_val)
    return bytes(buf), f"checksum:{current:#06x}->{new_val:#06x}"


def mutate_field(data: bytes, rng: random.Random) -> tuple[bytes, str]:
    """Mutate a specific header field with a semantically interesting value."""
    if len(data) < HEADER_SIZE:
        return data, "too_short"
    buf = bytearray(data)

    choice = rng.randint(0, 5)
    desc = ""

    if choice == 0:
        # Bad version
        ver = rng.choice([0, 1, 4, 6, 7, 9, 15])
        buf[0] = (ver << 4) | (buf[0] & 0x0F)
        desc = f"version={ver}"
    elif choice == 1:
        # Bad IHL
        ihl = rng.choice([0, 1, 5, 6, 8, 15])
        buf[0] = (buf[0] & 0xF0) | ihl
        desc = f"ihl={ihl}"
    elif choice == 2:
        # total_length < HEADER_SIZE
        val = rng.randint(0, HEADER_SIZE - 1)
        struct.pack_into("!H", buf, 2, val)
        desc = f"total_length={val}(<28)"
    elif choice == 3:
        # total_length > actual data
        val = len(data) + rng.randint(1, 1000)
        struct.pack_into("!H", buf, 2, min(val, 65535))
        desc = f"total_length={min(val, 65535)}(>actual:{len(data)})"
    elif choice == 4:
        # Reserved flag set + DF + MF simultaneously
        flags = 0b111
        frag_off = rng.randint(0, 8191)
        val = (flags << 13) | frag_off
        struct.pack_into("!H", buf, 6, val)
        desc = f"flags=0b111,frag_off={frag_off}"
    elif choice == 5:
        # Reserved addresses (127.x for internal zone)
        struct.pack_into("!I", buf, 12, 0x7F000001)  # 127.0.0.1
        desc = "src_asn=127.0.0.1(internal)"

    return bytes(buf), f"field_mutate:{desc}"


def mutate_fragment(data: bytes, rng: random.Random) -> tuple[bytes, str]:
    """Generate a malformed fragment."""
    if len(data) < HEADER_SIZE:
        return data, "too_short"
    buf = bytearray(data)

    choice = rng.randint(0, 3)
    desc = ""

    if choice == 0:
        # Overlapping fragment: MF=1 with offset 0 and small payload
        flags = 0b001  # MF=1
        frag_off = 0
        struct.pack_into("!H", buf, 6, (flags << 13) | frag_off)
        desc = "mf=1,off=0(overlap_start)"
    elif choice == 1:
        # Fragment with huge offset (beyond 65535 reassembly)
        flags = 0b001  # MF=1
        frag_off = 8191  # max offset
        struct.pack_into("!H", buf, 6, (flags << 13) | frag_off)
        desc = f"mf=1,off={frag_off}(max)"
    elif choice == 2:
        # Last fragment with non-zero offset and payload that exceeds 65535
        flags = 0b000  # MF=0 (last)
        frag_off = 8000
        struct.pack_into("!H", buf, 6, (flags << 13) | frag_off)
        # Set total_length to include large payload suggestion
        struct.pack_into("!H", buf, 2, HEADER_SIZE + 200)
        desc = f"mf=0,off={frag_off}(overflow)"
    elif choice == 3:
        # DF=1 with non-zero fragment offset (contradiction)
        flags = 0b010  # DF=1
        frag_off = rng.randint(1, 100)
        struct.pack_into("!H", buf, 6, (flags << 13) | frag_off)
        desc = f"df=1,off={frag_off}(contradiction)"

    return bytes(buf), f"fragment:{desc}"


# Mutation dispatch
_STRATEGY_MAP: dict[FuzzStrategy, object] = {
    FuzzStrategy.BIT_FLIP: mutate_bit_flip,
    FuzzStrategy.BYTE_RANDOM: mutate_byte_random,
    FuzzStrategy.BOUNDARY: mutate_boundary,
    FuzzStrategy.TRUNCATE: mutate_truncate,
    FuzzStrategy.EXTEND: mutate_extend,
    FuzzStrategy.CHECKSUM: mutate_checksum,
    FuzzStrategy.FIELD_MUTATE: mutate_field,
    FuzzStrategy.FRAGMENT: mutate_fragment,
}


# ---------------------------------------------------------------------------
# Fuzzer
# ---------------------------------------------------------------------------


class Fuzzer:
    """Packet fuzzer for IPv8 protocol security testing.

    Generates mutated packets and optionally tests them against
    the parser/security subsystem to find crashes and anomalies.
    """

    def __init__(self, seed: int = 0, config: FuzzConfig | None = None) -> None:
        self._seed = seed or int.from_bytes(os.urandom(4), "big")
        self._rng = random.Random(self._seed)
        self._config = config or FuzzConfig(seed=self._seed)
        self._cases: list[FuzzCase] = []
        self._result: FuzzResult | None = None

    @property
    def seed(self) -> int:
        return self._seed

    @property
    def config(self) -> FuzzConfig:
        return self._config

    @property
    def cases(self) -> list[FuzzCase]:
        return list(self._cases)

    @property
    def result(self) -> FuzzResult | None:
        return self._result

    def generate_case(self, case_id: int, strategy: FuzzStrategy | None = None) -> FuzzCase:
        """Generate a single fuzz case."""
        if strategy is None:
            strategy = self._rng.choice(list(FuzzStrategy))

        # Start with a valid packet
        payload_size = self._rng.randint(0, 128)
        payload = bytes(self._rng.randint(0, 255) for _ in range(payload_size))
        base_packet = build_valid_packet(
            src_asn=self._rng.randint(1, 100000),
            dst_asn=self._rng.randint(1, 100000),
            payload=payload,
            ttl=self._rng.randint(1, 255),
            protocol=self._rng.choice([1, 6, 17, 253]),
            tos=self._rng.randint(0, 255),
            identification=self._rng.randint(0, 0xFFFF),
        )

        mutations: list[str] = []

        if strategy == FuzzStrategy.COMBINED:
            # Apply 2-4 random mutations
            data = base_packet
            num_mutations = self._rng.randint(2, 4)
            strategies = [s for s in FuzzStrategy if s != FuzzStrategy.COMBINED]
            for _ in range(num_mutations):
                strat = self._rng.choice(strategies)
                mutator = _STRATEGY_MAP[strat]
                data, desc = mutator(data, self._rng)  # type: ignore[operator]
                mutations.append(f"{strat.value}:{desc}")
        else:
            mutator = _STRATEGY_MAP[strategy]
            data, desc = mutator(base_packet, self._rng)  # type: ignore[operator]
            mutations.append(f"{strategy.value}:{desc}")

        case = FuzzCase(
            case_id=case_id,
            strategy=strategy,
            raw_bytes=data,
            description=f"seed={self._seed},id={case_id}",
            mutations=mutations,
        )
        return case

    def generate_cases(self, count: int | None = None) -> list[FuzzCase]:
        """Generate multiple fuzz cases."""
        n = count or self._config.count
        self._cases = [self.generate_case(i) for i in range(n)]
        return self._cases

    def run(self, count: int | None = None, target: FuzzTarget | None = None) -> FuzzResult:
        """Run the fuzzer against the specified target.

        Generates cases and attempts to parse them, recording crashes.
        """
        from ipv8lab.packet import IPv8Packet

        n = count or self._config.count
        _ = target or self._config.target  # reserved for future target-specific logic

        if not self._cases:
            self.generate_cases(n)

        result = FuzzResult(total_cases=len(self._cases))
        findings: list[FuzzFinding] = []

        for case in self._cases:
            try:
                # Try parsing the fuzzed packet
                IPv8Packet.from_bytes(case.raw_bytes, verify=False)
            except (struct.error, OverflowError) as e:
                result.crashes += 1
                findings.append(FuzzFinding(
                    case_id=case.case_id,
                    severity=FuzzSeverity.HIGH,
                    category="crash",
                    description=f"Parser crash on {case.strategy.value}",
                    exception_type=type(e).__name__,
                    exception_msg=str(e)[:200],
                ))
            except Exception as e:
                result.errors += 1
                findings.append(FuzzFinding(
                    case_id=case.case_id,
                    severity=FuzzSeverity.MEDIUM,
                    category="error",
                    description=f"Parser error on {case.strategy.value}",
                    exception_type=type(e).__name__,
                    exception_msg=str(e)[:200],
                ))

        result.findings = findings
        result.cases = self._cases
        self._result = result
        return result

    def run_dry(self, count: int | None = None) -> FuzzResult:
        """Generate cases without executing against parser (for testing)."""
        n = count or self._config.count
        if not self._cases:
            self.generate_cases(n)

        result = FuzzResult(total_cases=len(self._cases), cases=self._cases)
        self._result = result
        return result

    def to_dict(self) -> dict[str, object]:
        return {
            "seed": self._seed,
            "config": self._config.to_dict(),
            "cases_generated": len(self._cases),
            "result": self._result.to_dict() if self._result else None,
        }

    def reset(self) -> None:
        """Reset fuzzer state."""
        self._rng = random.Random(self._seed)
        self._cases.clear()
        self._result = None
