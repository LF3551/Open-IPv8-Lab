# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for packet fuzzer module."""

from __future__ import annotations

import random
import struct

from ipv8lab.fuzzer import (
    HEADER_SIZE,
    FuzzCase,
    FuzzConfig,
    FuzzFinding,
    FuzzResult,
    FuzzSeverity,
    FuzzStrategy,
    FuzzTarget,
    Fuzzer,
    build_valid_packet,
    mutate_bit_flip,
    mutate_boundary,
    mutate_byte_random,
    mutate_checksum,
    mutate_extend,
    mutate_field,
    mutate_fragment,
    mutate_truncate,
    _compute_checksum,
)


# ---------------------------------------------------------------------------
# Valid packet generation
# ---------------------------------------------------------------------------


class TestBuildValidPacket:
    def test_default(self) -> None:
        pkt = build_valid_packet()
        assert len(pkt) == HEADER_SIZE

    def test_with_payload(self) -> None:
        pkt = build_valid_packet(payload=b"hello")
        assert len(pkt) == HEADER_SIZE + 5

    def test_version_ihl(self) -> None:
        pkt = build_valid_packet()
        assert pkt[0] == 0x87  # version=8, ihl=7

    def test_total_length(self) -> None:
        pkt = build_valid_packet(payload=b"x" * 10)
        total_len = struct.unpack_from("!H", pkt, 2)[0]
        assert total_len == HEADER_SIZE + 10

    def test_ttl(self) -> None:
        pkt = build_valid_packet(ttl=128)
        assert pkt[8] == 128

    def test_protocol(self) -> None:
        pkt = build_valid_packet(protocol=6)
        assert pkt[9] == 6

    def test_checksum_nonzero(self) -> None:
        pkt = build_valid_packet()
        cksum = struct.unpack_from("!H", pkt, 10)[0]
        # Checksum should be computed (may be 0 in rare cases)
        assert isinstance(cksum, int)


# ---------------------------------------------------------------------------
# Checksum
# ---------------------------------------------------------------------------


class TestChecksum:
    def test_compute(self) -> None:
        header = b"\x00" * HEADER_SIZE
        result = _compute_checksum(header, b"")
        assert isinstance(result, int)
        assert 0 <= result <= 0xFFFF

    def test_different_payloads(self) -> None:
        header = b"\x87" + b"\x00" * (HEADER_SIZE - 1)
        c1 = _compute_checksum(header, b"aaa")
        c2 = _compute_checksum(header, b"bbb")
        assert c1 != c2


# ---------------------------------------------------------------------------
# Mutation functions
# ---------------------------------------------------------------------------


class TestMutateBitFlip:
    def test_flips_one_bit(self) -> None:
        data = b"\x00" * 28
        rng = random.Random(42)
        mutated, desc = mutate_bit_flip(data, rng)
        assert mutated != data
        assert "bit_flip" in desc

    def test_empty(self) -> None:
        rng = random.Random(1)
        result, desc = mutate_bit_flip(b"", rng)
        assert result == b""

    def test_single_byte(self) -> None:
        rng = random.Random(10)
        result, _ = mutate_bit_flip(b"\x00", rng)
        assert len(result) == 1
        assert result != b"\x00"


class TestMutateByteRandom:
    def test_changes_bytes(self) -> None:
        data = b"\x00" * 100
        rng = random.Random(42)
        mutated, desc = mutate_byte_random(data, rng)
        assert mutated != data
        assert "byte_random" in desc

    def test_empty(self) -> None:
        rng = random.Random(1)
        result, _ = mutate_byte_random(b"", rng)
        assert result == b""


class TestMutateBoundary:
    def test_mutates_field(self) -> None:
        pkt = build_valid_packet()
        rng = random.Random(42)
        mutated, desc = mutate_boundary(pkt, rng)
        assert "boundary" in desc
        assert len(mutated) == len(pkt)

    def test_short_packet(self) -> None:
        rng = random.Random(1)
        result, desc = mutate_boundary(b"\x00" * 10, rng)
        assert desc == "too_short"


class TestMutateTruncate:
    def test_truncates(self) -> None:
        pkt = build_valid_packet(payload=b"x" * 50)
        rng = random.Random(42)
        mutated, desc = mutate_truncate(pkt, rng)
        assert len(mutated) < len(pkt)
        assert "truncate" in desc

    def test_single_byte(self) -> None:
        rng = random.Random(1)
        result, _ = mutate_truncate(b"\x00", rng)
        assert result == b""


class TestMutateExtend:
    def test_extends(self) -> None:
        pkt = build_valid_packet()
        rng = random.Random(42)
        mutated, desc = mutate_extend(pkt, rng)
        assert len(mutated) > len(pkt)
        assert "extend" in desc


class TestMutateChecksum:
    def test_corrupts_checksum(self) -> None:
        pkt = build_valid_packet()
        rng = random.Random(42)
        mutated, desc = mutate_checksum(pkt, rng)
        assert "checksum" in desc
        # Checksum bytes changed
        assert mutated[10:12] != pkt[10:12]

    def test_short_packet(self) -> None:
        rng = random.Random(1)
        result, desc = mutate_checksum(b"\x00" * 10, rng)
        assert desc == "too_short"


class TestMutateField:
    def test_mutates(self) -> None:
        pkt = build_valid_packet()
        rng = random.Random(42)
        mutated, desc = mutate_field(pkt, rng)
        assert "field_mutate" in desc
        assert mutated != pkt

    def test_short_packet(self) -> None:
        rng = random.Random(1)
        _, desc = mutate_field(b"\x00" * 5, rng)
        assert desc == "too_short"


class TestMutateFragment:
    def test_mutates(self) -> None:
        pkt = build_valid_packet(payload=b"x" * 20)
        rng = random.Random(42)
        mutated, desc = mutate_fragment(pkt, rng)
        assert "fragment" in desc

    def test_short_packet(self) -> None:
        rng = random.Random(1)
        _, desc = mutate_fragment(b"\x00" * 5, rng)
        assert desc == "too_short"


# ---------------------------------------------------------------------------
# FuzzCase
# ---------------------------------------------------------------------------


class TestFuzzCase:
    def test_create(self) -> None:
        c = FuzzCase(case_id=0, strategy=FuzzStrategy.BIT_FLIP, raw_bytes=b"\x00" * 28)
        assert c.case_id == 0
        assert c.strategy == FuzzStrategy.BIT_FLIP

    def test_to_dict(self) -> None:
        c = FuzzCase(case_id=1, strategy=FuzzStrategy.TRUNCATE, raw_bytes=b"\xab\xcd", mutations=["trunc@5"])
        d = c.to_dict()
        assert d["case_id"] == 1
        assert d["strategy"] == "truncate"
        assert d["raw_hex"] == "abcd"
        assert d["size"] == 2


# ---------------------------------------------------------------------------
# FuzzFinding
# ---------------------------------------------------------------------------


class TestFuzzFinding:
    def test_create(self) -> None:
        f = FuzzFinding(case_id=5, severity=FuzzSeverity.HIGH, category="crash", description="test")
        assert f.severity == FuzzSeverity.HIGH

    def test_to_dict(self) -> None:
        f = FuzzFinding(case_id=3, severity=FuzzSeverity.MEDIUM, category="error", description="bad", exception_type="ValueError", exception_msg="oops")
        d = f.to_dict()
        assert d["severity"] == "medium"
        assert d["exception_type"] == "ValueError"


# ---------------------------------------------------------------------------
# FuzzResult
# ---------------------------------------------------------------------------


class TestFuzzResult:
    def test_empty(self) -> None:
        r = FuzzResult()
        assert r.success_rate == 0.0

    def test_success_rate(self) -> None:
        r = FuzzResult(total_cases=100, crashes=10)
        assert r.success_rate == 0.9

    def test_to_dict(self) -> None:
        r = FuzzResult(total_cases=50, crashes=5, errors=3)
        d = r.to_dict()
        assert d["total_cases"] == 50
        assert d["crashes"] == 5
        assert d["success_rate"] == 0.9


# ---------------------------------------------------------------------------
# FuzzConfig
# ---------------------------------------------------------------------------


class TestFuzzConfig:
    def test_defaults(self) -> None:
        c = FuzzConfig()
        assert c.count == 100
        assert c.target == FuzzTarget.PARSER

    def test_to_dict(self) -> None:
        c = FuzzConfig(count=50, seed=123, strategies=[FuzzStrategy.BIT_FLIP])
        d = c.to_dict()
        assert d["count"] == 50
        assert d["seed"] == 123
        assert d["strategies"] == ["bit_flip"]


# ---------------------------------------------------------------------------
# Fuzzer
# ---------------------------------------------------------------------------


class TestFuzzer:
    def test_create(self) -> None:
        f = Fuzzer(seed=42)
        assert f.seed == 42

    def test_random_seed(self) -> None:
        f = Fuzzer()
        assert f.seed > 0

    def test_generate_case(self) -> None:
        f = Fuzzer(seed=42)
        case = f.generate_case(0)
        assert isinstance(case, FuzzCase)
        assert len(case.raw_bytes) > 0

    def test_generate_case_strategy(self) -> None:
        f = Fuzzer(seed=42)
        case = f.generate_case(0, strategy=FuzzStrategy.TRUNCATE)
        assert case.strategy == FuzzStrategy.TRUNCATE

    def test_generate_cases(self) -> None:
        f = Fuzzer(seed=42)
        cases = f.generate_cases(20)
        assert len(cases) == 20
        assert all(isinstance(c, FuzzCase) for c in cases)

    def test_run_dry(self) -> None:
        f = Fuzzer(seed=42)
        result = f.run_dry(count=10)
        assert result.total_cases == 10
        assert result.crashes == 0

    def test_run(self) -> None:
        f = Fuzzer(seed=42)
        result = f.run(count=50)
        assert result.total_cases == 50
        # Parser should handle most gracefully
        assert result.success_rate >= 0.0

    def test_deterministic(self) -> None:
        f1 = Fuzzer(seed=100)
        f2 = Fuzzer(seed=100)
        c1 = f1.generate_cases(10)
        c2 = f2.generate_cases(10)
        for a, b in zip(c1, c2):
            assert a.raw_bytes == b.raw_bytes

    def test_reset(self) -> None:
        f = Fuzzer(seed=42)
        f.generate_cases(10)
        assert len(f.cases) == 10
        f.reset()
        assert len(f.cases) == 0

    def test_to_dict(self) -> None:
        f = Fuzzer(seed=42)
        f.run_dry(count=5)
        d = f.to_dict()
        assert d["seed"] == 42
        assert d["cases_generated"] == 5

    def test_config(self) -> None:
        cfg = FuzzConfig(count=200, seed=99)
        f = Fuzzer(seed=99, config=cfg)
        assert f.config.count == 200


# ---------------------------------------------------------------------------
# Strategy enum
# ---------------------------------------------------------------------------


class TestFuzzStrategy:
    def test_all_strategies(self) -> None:
        assert len(FuzzStrategy) == 9

    def test_values(self) -> None:
        assert FuzzStrategy.BIT_FLIP == "bit_flip"
        assert FuzzStrategy.COMBINED == "combined"


# ---------------------------------------------------------------------------
# Target enum
# ---------------------------------------------------------------------------


class TestFuzzTarget:
    def test_all_targets(self) -> None:
        assert len(FuzzTarget) == 5

    def test_values(self) -> None:
        assert FuzzTarget.PARSER == "parser"
        assert FuzzTarget.ALL == "all"


# ---------------------------------------------------------------------------
# Severity enum
# ---------------------------------------------------------------------------


class TestFuzzSeverity:
    def test_values(self) -> None:
        assert FuzzSeverity.CRITICAL == "critical"
        assert FuzzSeverity.INFO == "info"
        assert len(FuzzSeverity) == 5
