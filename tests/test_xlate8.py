# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for the unified XLATE8 subsystem (xlate8.py)."""

from __future__ import annotations

import pytest

from ipv8lab.address import IPv8Address
from ipv8lab.companions import XLATE8Entry
from ipv8lab.packet import IPv8Packet
from ipv8lab.xlate8 import (
    TranslationResult,
    Xlate8,
    Xlate8Mode,
    _build_encap_frame,
    _strip_encap_frame,
)


def _pkt(src: str = "64496-10.0.0.1", dst: str = "64497-10.0.0.2", payload: bytes = b"x") -> IPv8Packet:
    return IPv8Packet(
        src=IPv8Address.parse(src),
        dst=IPv8Address.parse(dst),
        payload=payload,
    )


def _entry(
    internal: str = "64496-10.0.0.1",
    external: str = "64497-10.0.0.1",
    proto: int = 6,
    int_port: int = 0,
    ext_port: int = 0,
) -> XLATE8Entry:
    return XLATE8Entry(
        internal_address=internal,
        external_address=external,
        protocol=proto,
        internal_port=int_port,
        external_port=ext_port,
        dns_validated=True,
    )


# ---------------------------------------------------------------------------
# Xlate8Mode enum
# ---------------------------------------------------------------------------

class TestXlate8Mode:
    def test_five_modes(self) -> None:
        assert len(Xlate8Mode) == 5

    def test_native_is_1(self) -> None:
        assert Xlate8Mode.NATIVE == 1

    def test_four_to_eight_is_2(self) -> None:
        assert Xlate8Mode.FOUR_TO_EIGHT == 2

    def test_eight_to_four_is_3(self) -> None:
        assert Xlate8Mode.EIGHT_TO_FOUR == 3

    def test_napt_rn_is_4(self) -> None:
        assert Xlate8Mode.NAPT_RN == 4

    def test_encap_is_5(self) -> None:
        assert Xlate8Mode.ENCAP == 5


# ---------------------------------------------------------------------------
# Xlate8 default construction
# ---------------------------------------------------------------------------

class TestXlate8Defaults:
    def test_default_mode_is_native(self) -> None:
        gw = Xlate8()
        assert gw.mode == Xlate8Mode.NATIVE

    def test_default_local_rn_zero(self) -> None:
        assert Xlate8().local_rn == 0

    def test_entry_count_zero(self) -> None:
        assert Xlate8().entry_count == 0

    def test_to_dict(self) -> None:
        gw = Xlate8(mode=Xlate8Mode.NAPT_RN, local_rn=64496)
        d = gw.to_dict()
        assert d["mode"] == "NAPT_RN"
        assert d["local_rn"] == 64496

    def test_install_entry(self) -> None:
        gw = Xlate8()
        gw.install(_entry())
        assert gw.entry_count == 1

    def test_install_rejects_unvalidated(self) -> None:
        gw = Xlate8()
        bad = XLATE8Entry(
            internal_address="64496-10.0.0.1",
            external_address="64497-10.0.0.1",
            dns_validated=False,
        )
        assert gw.install(bad) is False
        assert gw.entry_count == 0


# ---------------------------------------------------------------------------
# Mode 1: NATIVE
# ---------------------------------------------------------------------------

class TestModeNative:
    def test_passthrough_success(self) -> None:
        gw = Xlate8(mode=Xlate8Mode.NATIVE)
        pkt = _pkt()
        result = gw.translate(pkt)
        assert result.success is True
        assert result.packet is pkt

    def test_reverse_passthrough(self) -> None:
        gw = Xlate8(mode=Xlate8Mode.NATIVE)
        pkt = _pkt()
        result = gw.reverse_translate(pkt)
        assert result.success is True
        assert result.packet is pkt

    def test_result_type(self) -> None:
        gw = Xlate8(mode=Xlate8Mode.NATIVE)
        result = gw.translate(_pkt())
        assert isinstance(result, TranslationResult)
        assert result.mode == Xlate8Mode.NATIVE


# ---------------------------------------------------------------------------
# Mode 2: FOUR_TO_EIGHT
# ---------------------------------------------------------------------------

class TestModeFourToEight:
    def test_no_entry_returns_failure(self) -> None:
        gw = Xlate8(mode=Xlate8Mode.FOUR_TO_EIGHT)
        result = gw.translate(_pkt())
        assert result.success is False
        assert result.packet is None

    def test_with_entry_rewrites_src(self) -> None:
        gw = Xlate8(mode=Xlate8Mode.FOUR_TO_EIGHT)
        gw.install(_entry(internal="64496-10.0.0.1", external="64498-10.0.0.1"))
        pkt = _pkt(src="64496-10.0.0.1", dst="64497-10.0.0.2")
        result = gw.translate(pkt, src_port=0)
        assert result.success is True
        assert result.packet is not None
        assert result.packet.src.rn == 64498

    def test_reverse_translates_back(self) -> None:
        gw = Xlate8(mode=Xlate8Mode.FOUR_TO_EIGHT)
        gw.install(_entry(internal="64496-10.0.0.1", external="64498-10.0.0.1", ext_port=0))
        pkt = _pkt(src="64497-10.0.0.2", dst="64498-10.0.0.1")
        result = gw.reverse_translate(pkt, dst_port=0)
        assert result.success is True
        assert result.packet is not None
        assert result.packet.dst.rn == 64496

    def test_reverse_no_entry_failure(self) -> None:
        gw = Xlate8(mode=Xlate8Mode.FOUR_TO_EIGHT)
        result = gw.reverse_translate(_pkt(), dst_port=0)
        assert result.success is False


# ---------------------------------------------------------------------------
# Mode 3: EIGHT_TO_FOUR
# ---------------------------------------------------------------------------

class TestModeEightToFour:
    def test_dst_rn_zero_passthrough(self) -> None:
        gw = Xlate8(mode=Xlate8Mode.EIGHT_TO_FOUR)
        pkt = _pkt(src="64496-10.0.0.1", dst="0-192.0.2.1")
        result = gw.translate(pkt)
        assert result.success is True
        assert result.packet is pkt

    def test_dst_nonzero_no_entry_blocked(self) -> None:
        gw = Xlate8(mode=Xlate8Mode.EIGHT_TO_FOUR)
        result = gw.translate(_pkt())
        assert result.success is False

    def test_dst_rewrite_via_state_table(self) -> None:
        gw = Xlate8(mode=Xlate8Mode.EIGHT_TO_FOUR)
        gw.install(_entry(internal="64497-10.0.0.2", external="0-192.0.2.1"))
        pkt = _pkt(src="64496-10.0.0.1", dst="64497-10.0.0.2")
        result = gw.translate(pkt)
        assert result.success is True
        assert result.packet is not None
        assert result.packet.dst.rn == 0


# ---------------------------------------------------------------------------
# Mode 4: NAPT_RN
# ---------------------------------------------------------------------------

class TestModeNaptRn:
    def test_no_local_rn_fails(self) -> None:
        gw = Xlate8(mode=Xlate8Mode.NAPT_RN, local_rn=0)
        result = gw.translate(_pkt())
        assert result.success is False

    def test_auto_rn_rewrite(self) -> None:
        gw = Xlate8(mode=Xlate8Mode.NAPT_RN, local_rn=64498)
        pkt = _pkt(src="64496-10.0.0.1", dst="64497-10.0.0.2")
        result = gw.translate(pkt)
        assert result.success is True
        assert result.packet is not None
        assert result.packet.src.rn == 64498

    def test_la_preserved_in_rn_rewrite(self) -> None:
        gw = Xlate8(mode=Xlate8Mode.NAPT_RN, local_rn=64498)
        pkt = _pkt(src="64496-10.1.2.3")
        result = gw.translate(pkt)
        assert result.success is True
        assert result.packet.src.la_str == "10.1.2.3"

    def test_state_table_mapping_wins(self) -> None:
        gw = Xlate8(mode=Xlate8Mode.NAPT_RN, local_rn=64498)
        gw.install(_entry(internal="64496-10.0.0.1", external="64500-10.0.0.1"))
        pkt = _pkt(src="64496-10.0.0.1")
        result = gw.translate(pkt)
        assert result.packet.src.rn == 64500

    def test_reverse_via_state_table(self) -> None:
        gw = Xlate8(mode=Xlate8Mode.NAPT_RN, local_rn=64498)
        gw.install(_entry(internal="64496-10.0.0.1", external="64500-10.0.0.1", ext_port=0))
        pkt = _pkt(src="64497-1.1.1.1", dst="64500-10.0.0.1")
        result = gw.reverse_translate(pkt, dst_port=0)
        assert result.success is True
        assert result.packet.dst.rn == 64496


# ---------------------------------------------------------------------------
# Mode 5: ENCAP
# ---------------------------------------------------------------------------

class TestModeEncap:
    def test_no_config_fails(self) -> None:
        gw = Xlate8(mode=Xlate8Mode.ENCAP)
        result = gw.translate(_pkt())
        assert result.success is False

    def test_encap_wraps_packet(self) -> None:
        gw = Xlate8(
            mode=Xlate8Mode.ENCAP,
            encap_src_ipv4="192.0.2.1",
            encap_dst_ipv4="192.0.2.2",
        )
        pkt = _pkt()
        result = gw.translate(pkt)
        assert result.success is True
        assert result.packet is not None
        # payload should be longer than original (IPv4 header added)
        assert len(result.packet.payload) > len(pkt.to_bytes())

    def test_decap_recovers_inner(self) -> None:
        gw = Xlate8(
            mode=Xlate8Mode.ENCAP,
            encap_src_ipv4="192.0.2.1",
            encap_dst_ipv4="192.0.2.2",
        )
        original = _pkt(payload=b"encap-me")
        enc_result = gw.translate(original)
        assert enc_result.success

        dec_result = gw.reverse_translate(enc_result.packet)
        assert dec_result.success
        assert dec_result.packet.payload == b"encap-me"

    def test_encap_uses_proto_253(self) -> None:
        import struct
        raw = _build_encap_frame(b"\x00" * 28, "192.0.2.1", "192.0.2.2")
        proto = raw[9]
        assert proto == 253  # noqa: PLR2004

    def test_strip_encap_invalid_proto_returns_none(self) -> None:
        # Build a fake IPv4 frame with proto=6 (TCP)
        import struct
        hdr = bytes([0x45, 0, 0, 48, 0, 0, 0, 0, 64, 6, 0, 0]) + b"\xc0\x00\x02\x01\xc0\x00\x02\x02"
        result = _strip_encap_frame(hdr + b"\x00" * 28)
        assert result is None

    def test_strip_encap_too_short_returns_none(self) -> None:
        assert _strip_encap_frame(b"\x00" * 5) is None


# ---------------------------------------------------------------------------
# Build / strip encap helpers
# ---------------------------------------------------------------------------

class TestEncapHelpers:
    def test_roundtrip(self) -> None:
        inner = b"\x45" * 28
        frame = _build_encap_frame(inner, "10.0.0.1", "10.0.0.2")
        recovered = _strip_encap_frame(frame)
        assert recovered == inner

    def test_frame_has_ipv4_header(self) -> None:
        frame = _build_encap_frame(b"\x00" * 28, "1.2.3.4", "5.6.7.8")
        # First byte: version=4, IHL=5
        assert frame[0] == 0x45  # noqa: PLR2004
