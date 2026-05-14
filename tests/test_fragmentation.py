# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for IPv8 fragmentation and reassembly module."""

from __future__ import annotations

import pytest

from ipv8lab.address import IPv8Address
from ipv8lab.fragmentation import (
    DEFAULT_MTU,
    FLAG_DF,
    FLAG_MF,
    FRAG_UNIT,
    HEADER_SIZE,
    MIN_MTU,
    FragmentationError,
    Reassembler,
    can_fragment,
    fragment,
    fragment_and_reassemble,
    is_fragment,
    needs_fragmentation,
)
from ipv8lab.packet import IPv8Packet


def _pkt(payload_size: int = 100, flags: int = 0, identification: int = 1) -> IPv8Packet:
    return IPv8Packet(
        src=IPv8Address.parse("64496.10.0.1.1"),
        dst=IPv8Address.parse("64497.10.0.1.100"),
        payload=bytes(range(256)) * (payload_size // 256) + bytes(range(payload_size % 256)),
        identification=identification,
        flags=flags,
    )


# ---------------------------------------------------------------------------
# fragment()
# ---------------------------------------------------------------------------

class TestFragment:
    def test_no_fragmentation_needed(self) -> None:
        frags = fragment(_pkt(100), mtu=1500)
        assert len(frags) == 1
        assert frags[0].flags & FLAG_MF == 0

    def test_exact_mtu(self) -> None:
        size = DEFAULT_MTU - HEADER_SIZE
        frags = fragment(_pkt(size), mtu=DEFAULT_MTU)
        assert len(frags) == 1

    def test_one_byte_over(self) -> None:
        size = DEFAULT_MTU - HEADER_SIZE + 1
        frags = fragment(_pkt(size), mtu=DEFAULT_MTU)
        assert len(frags) == 2

    def test_fragments_have_mf(self) -> None:
        frags = fragment(_pkt(3000), mtu=1500)
        assert len(frags) >= 2
        for f in frags[:-1]:
            assert f.flags & FLAG_MF
        assert not (frags[-1].flags & FLAG_MF)

    def test_fragment_offsets_ascending(self) -> None:
        frags = fragment(_pkt(5000), mtu=1500)
        offsets = [f.fragment_offset for f in frags]
        assert offsets == sorted(offsets)
        assert offsets[0] == 0

    def test_fragment_payload_multiple_of_8(self) -> None:
        frags = fragment(_pkt(5000), mtu=1500)
        for f in frags[:-1]:
            assert len(f.payload) % FRAG_UNIT == 0

    def test_total_payload_preserved(self) -> None:
        pkt = _pkt(5000)
        frags = fragment(pkt, mtu=1500)
        reassembled = b""
        for f in sorted(frags, key=lambda x: x.fragment_offset):
            reassembled += f.payload
        assert reassembled == pkt.payload

    def test_identification_preserved(self) -> None:
        frags = fragment(_pkt(3000, identification=42), mtu=1500)
        for f in frags:
            assert f.identification == 42

    def test_custom_identification(self) -> None:
        frags = fragment(_pkt(3000), mtu=1500, identification=99)
        for f in frags:
            assert f.identification == 99

    def test_src_dst_preserved(self) -> None:
        pkt = _pkt(3000)
        frags = fragment(pkt, mtu=1500)
        for f in frags:
            assert f.src == pkt.src
            assert f.dst == pkt.dst

    def test_ttl_protocol_preserved(self) -> None:
        pkt = _pkt(3000)
        frags = fragment(pkt, mtu=1500)
        for f in frags:
            assert f.ttl == pkt.ttl
            assert f.protocol == pkt.protocol

    def test_df_raises(self) -> None:
        with pytest.raises(FragmentationError, match="DF flag"):
            fragment(_pkt(3000, flags=FLAG_DF), mtu=1500)

    def test_mtu_too_small(self) -> None:
        with pytest.raises(FragmentationError, match="below minimum"):
            fragment(_pkt(100), mtu=MIN_MTU - 1)

    def test_tiny_mtu(self) -> None:
        frags = fragment(_pkt(1000), mtu=MIN_MTU)
        assert len(frags) > 1
        for f in frags[:-1]:
            assert len(f.payload) == FRAG_UNIT

    def test_fragment_sizes_within_mtu(self) -> None:
        for mtu in [64, 100, 500, 1000, 1500]:
            frags = fragment(_pkt(5000), mtu=mtu)
            for f in frags:
                assert HEADER_SIZE + len(f.payload) <= mtu


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class TestHelpers:
    def test_needs_fragmentation_true(self) -> None:
        assert needs_fragmentation(_pkt(3000), mtu=1500)

    def test_needs_fragmentation_false(self) -> None:
        assert not needs_fragmentation(_pkt(100), mtu=1500)

    def test_can_fragment_true(self) -> None:
        assert can_fragment(_pkt(100))

    def test_can_fragment_false(self) -> None:
        assert not can_fragment(_pkt(100, flags=FLAG_DF))

    def test_is_fragment_mf(self) -> None:
        pkt = _pkt(100)
        pkt.flags = FLAG_MF
        assert is_fragment(pkt)

    def test_is_fragment_offset(self) -> None:
        pkt = _pkt(100)
        pkt.fragment_offset = 10
        assert is_fragment(pkt)

    def test_is_fragment_normal(self) -> None:
        assert not is_fragment(_pkt(100))


# ---------------------------------------------------------------------------
# Reassembler
# ---------------------------------------------------------------------------

class TestReassembler:
    def test_non_fragment_passthrough(self) -> None:
        ra = Reassembler()
        pkt = _pkt(100)
        result = ra.process(pkt)
        assert result is pkt
        assert ra.pending == 0

    def test_simple_reassembly(self) -> None:
        pkt = _pkt(3000)
        frags = fragment(pkt, mtu=1500)
        ra = Reassembler()
        results = [ra.process(f) for f in frags]
        non_none = [r for r in results if r is not None]
        assert len(non_none) == 1
        assert non_none[0].payload == pkt.payload

    def test_out_of_order(self) -> None:
        pkt = _pkt(3000)
        frags = fragment(pkt, mtu=1500)
        ra = Reassembler()
        # Send in reverse order
        results = [ra.process(f) for f in reversed(frags)]
        non_none = [r for r in results if r is not None]
        assert len(non_none) == 1
        assert non_none[0].payload == pkt.payload

    def test_pending_count(self) -> None:
        pkt = _pkt(3000)
        frags = fragment(pkt, mtu=1500)
        ra = Reassembler()
        ra.process(frags[0])
        assert ra.pending == 1

    def test_pending_cleared_after_reassembly(self) -> None:
        pkt = _pkt(3000)
        frags = fragment(pkt, mtu=1500)
        ra = Reassembler()
        for f in frags:
            ra.process(f)
        assert ra.pending == 0

    def test_multiple_packets(self) -> None:
        pkt1 = _pkt(2000, identification=1)
        pkt2 = _pkt(2000, identification=2)
        frags1 = fragment(pkt1, mtu=1000)
        frags2 = fragment(pkt2, mtu=1000)

        ra = Reassembler()
        # Interleave
        results = []
        for f1, f2 in zip(frags1, frags2):
            r = ra.process(f1)
            if r:
                results.append(r)
            r = ra.process(f2)
            if r:
                results.append(r)
        # Process remaining
        longer = frags1 if len(frags1) > len(frags2) else frags2
        for f in longer[len(min(frags1, frags2, key=len)):]:
            r = ra.process(f)
            if r:
                results.append(r)

        assert len(results) == 2

    def test_flush(self) -> None:
        pkt = _pkt(3000)
        frags = fragment(pkt, mtu=1500)
        ra = Reassembler()
        ra.process(frags[0])
        keys = ra.flush()
        assert len(keys) == 1
        assert ra.pending == 0

    def test_expire(self) -> None:
        pkt = _pkt(3000)
        frags = fragment(pkt, mtu=1500)
        ra = Reassembler(timeout=0.0)  # immediate expiry
        ra.process(frags[0])
        # Next process call will expire
        import time
        time.sleep(0.01)
        expired = ra.expire()
        assert len(expired) == 1
        assert ra.pending == 0

    def test_reassembled_flags_cleared(self) -> None:
        pkt = _pkt(3000)
        frags = fragment(pkt, mtu=1500)
        ra = Reassembler()
        result = None
        for f in frags:
            result = ra.process(f)
        assert result is not None
        assert result.flags == 0
        assert result.fragment_offset == 0


# ---------------------------------------------------------------------------
# Round-trip
# ---------------------------------------------------------------------------

class TestRoundTrip:
    @pytest.mark.parametrize("size", [1, 8, 100, 1472, 1473, 3000, 10000])
    def test_various_sizes(self, size: int) -> None:
        pkt = _pkt(size)
        result = fragment_and_reassemble(pkt, mtu=1500)
        assert result.payload == pkt.payload

    @pytest.mark.parametrize("mtu", [36, 64, 100, 500, 1000, 1500])
    def test_various_mtus(self, mtu: int) -> None:
        pkt = _pkt(3000)
        result = fragment_and_reassemble(pkt, mtu=mtu)
        assert result.payload == pkt.payload

    def test_single_byte_payload(self) -> None:
        pkt = _pkt(1)
        result = fragment_and_reassemble(pkt, mtu=36)
        assert result.payload == pkt.payload

    def test_empty_payload(self) -> None:
        pkt = IPv8Packet(
            src=IPv8Address.parse("64496.10.0.1.1"),
            dst=IPv8Address.parse("64497.10.0.1.100"),
            payload=b"",
        )
        result = fragment_and_reassemble(pkt, mtu=1500)
        assert result.payload == b""

    def test_preserves_addresses(self) -> None:
        pkt = _pkt(3000)
        result = fragment_and_reassemble(pkt, mtu=500)
        assert result.src == pkt.src
        assert result.dst == pkt.dst
