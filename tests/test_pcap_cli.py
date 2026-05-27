# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for PCAP CLI commands."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from ipv8lab.address import IPv8Address
from ipv8lab.capture import CapturedPacket, PacketCapture
from ipv8lab.cli.pcap_cli import app
from ipv8lab.packet import IPv8Packet
from ipv8lab.pcap_export import PcapWriter

runner = CliRunner()


def _make_pkt(
    src: str = "64496-10.0.1.1",
    dst: str = "64497-10.0.1.100",
    payload: bytes = b"test",
) -> IPv8Packet:
    return IPv8Packet(
        src=IPv8Address.parse(src),
        dst=IPv8Address.parse(dst),
        payload=payload,
    )


def _create_iv8cap(path: Path) -> None:
    cap = PacketCapture()
    cap._packets = [
        CapturedPacket(timestamp_ns=0, packet=_make_pkt(payload=b"iv8cap1")),
        CapturedPacket(timestamp_ns=500_000_000, packet=_make_pkt(payload=b"iv8cap2")),
    ]
    cap.save(path)


def _create_pcap(path: Path) -> None:
    w = PcapWriter()
    w.add_packet(_make_pkt(payload=b"pcap1"), timestamp_ns=0)
    w.add_packet(_make_pkt(payload=b"pcap2"), timestamp_ns=1_000_000_000)
    w.save(path)


# ---------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------

class TestExport:
    def test_export(self, tmp_path: Path) -> None:
        iv8cap = tmp_path / "test.iv8cap"
        _create_iv8cap(iv8cap)
        pcap = tmp_path / "test.pcap"
        result = runner.invoke(app, ["export", str(iv8cap), str(pcap)])
        assert result.exit_code == 0
        assert "2 packets" in result.output

    def test_export_json(self, tmp_path: Path) -> None:
        iv8cap = tmp_path / "test.iv8cap"
        _create_iv8cap(iv8cap)
        pcap = tmp_path / "test.pcap"
        result = runner.invoke(app, ["export", str(iv8cap), str(pcap), "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["packets"] == 2
        assert data["output"] == str(pcap)

    def test_export_missing_file(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["export", str(tmp_path / "none.iv8cap"), str(tmp_path / "out.pcap")])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# inspect
# ---------------------------------------------------------------------------

class TestInspect:
    def test_inspect(self, tmp_path: Path) -> None:
        pcap = tmp_path / "test.pcap"
        _create_pcap(pcap)
        result = runner.invoke(app, ["inspect", str(pcap)])
        assert result.exit_code == 0
        assert "10.0.1" in result.output

    def test_inspect_json(self, tmp_path: Path) -> None:
        pcap = tmp_path / "test.pcap"
        _create_pcap(pcap)
        result = runner.invoke(app, ["inspect", str(pcap), "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["total"] == 2
        assert len(data["packets"]) == 2

    def test_inspect_empty(self, tmp_path: Path) -> None:
        pcap = tmp_path / "test.pcap"
        PcapWriter().save(pcap)
        result = runner.invoke(app, ["inspect", str(pcap)])
        assert result.exit_code == 0
        assert "No IPv8 packets" in result.output

    def test_inspect_missing(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["inspect", str(tmp_path / "none.pcap")])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# write
# ---------------------------------------------------------------------------

class TestWrite:
    def test_write_default(self, tmp_path: Path) -> None:
        out = tmp_path / "w.pcap"
        result = runner.invoke(app, ["write", str(out)])
        assert result.exit_code == 0
        assert out.exists()
        assert "1 packet" in result.output

    def test_write_json(self, tmp_path: Path) -> None:
        out = tmp_path / "w.pcap"
        result = runner.invoke(app, ["write", str(out), "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["packets"] == 1

    def test_write_multiple(self, tmp_path: Path) -> None:
        out = tmp_path / "w.pcap"
        result = runner.invoke(app, ["write", str(out), "-n", "5"])
        assert result.exit_code == 0
        assert "5 packets" in result.output

    def test_write_custom_addrs(self, tmp_path: Path) -> None:
        out = tmp_path / "w.pcap"
        result = runner.invoke(app, [
            "write", str(out),
            "--src", "64500-10.0.0.1", "--dst", "64501-10.0.0.2",
            "--payload", "custom", "--json",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["packets"] == 1

    def test_write_bad_addr(self, tmp_path: Path) -> None:
        out = tmp_path / "w.pcap"
        result = runner.invoke(app, ["write", str(out), "--src", "bad"])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# dissector
# ---------------------------------------------------------------------------

class TestDissector:
    def test_dissector_stdout(self) -> None:
        result = runner.invoke(app, ["dissector"])
        assert result.exit_code == 0
        assert "Proto(" in result.output

    def test_dissector_json(self) -> None:
        result = runner.invoke(app, ["dissector", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "dissector" in data
        assert "Proto(" in data["dissector"]

    def test_dissector_file(self, tmp_path: Path) -> None:
        out = tmp_path / "ipv8.lua"
        result = runner.invoke(app, ["dissector", "-o", str(out)])
        assert result.exit_code == 0
        assert out.exists()

    def test_dissector_file_json(self, tmp_path: Path) -> None:
        out = tmp_path / "ipv8.lua"
        result = runner.invoke(app, ["dissector", "-o", str(out), "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["output"] == str(out)


# ---------------------------------------------------------------------------
# demo
# ---------------------------------------------------------------------------

class TestDemo:
    def test_demo(self, tmp_path: Path) -> None:
        out = tmp_path / "demo.pcap"
        result = runner.invoke(app, ["demo", "-o", str(out)])
        assert result.exit_code == 0
        assert "6 packets" in result.output
        assert out.exists()

    def test_demo_json(self, tmp_path: Path) -> None:
        out = tmp_path / "demo.pcap"
        result = runner.invoke(app, ["demo", "-o", str(out), "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["packets"] == 6
