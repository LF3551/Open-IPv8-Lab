# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for packet capture and replay."""

from __future__ import annotations

from pathlib import Path

import pytest

from ipv8lab.address import IPv8Address
from ipv8lab.capture import PacketCapture
from ipv8lab.packet import IPv8Packet


@pytest.fixture()
def sample_packets() -> list[IPv8Packet]:
    src = IPv8Address.parse("1.0.0.0.10.0.0.1")
    dst = IPv8Address.parse("2.0.0.0.10.0.0.2")
    return [
        IPv8Packet(src=src, dst=dst, payload=b"hello"),
        IPv8Packet(src=dst, dst=src, payload=b"world"),
    ]


class TestPacketCapture:
    def test_capture_and_count(self, sample_packets: list[IPv8Packet]) -> None:
        cap = PacketCapture()
        cap.start()
        for pkt in sample_packets:
            cap.capture(pkt)
        assert cap.count == 2

    def test_replay_order(self, sample_packets: list[IPv8Packet]) -> None:
        cap = PacketCapture()
        cap.start()
        for pkt in sample_packets:
            cap.capture(pkt)
        replay = cap.replay()
        assert len(replay) == 2
        assert replay[0][1].payload == b"hello"
        assert replay[1][1].payload == b"world"

    def test_timestamps_increasing(self, sample_packets: list[IPv8Packet]) -> None:
        cap = PacketCapture()
        cap.start()
        for pkt in sample_packets:
            cap.capture(pkt)
        replay = cap.replay()
        assert replay[0][0] <= replay[1][0]


class TestCaptureFile:
    def test_save_and_load(
        self, sample_packets: list[IPv8Packet], tmp_path: Path
    ) -> None:
        cap = PacketCapture()
        cap.start()
        for pkt in sample_packets:
            cap.capture(pkt)

        capfile = tmp_path / "test.iv8cap"
        cap.save(capfile)
        assert capfile.exists()

        loaded = PacketCapture.load(capfile)
        assert loaded.count == 2

        replay = loaded.replay()
        assert replay[0][1].payload == b"hello"
        assert replay[1][1].payload == b"world"

    def test_load_preserves_addresses(
        self, sample_packets: list[IPv8Packet], tmp_path: Path
    ) -> None:
        cap = PacketCapture()
        cap.start()
        for pkt in sample_packets:
            cap.capture(pkt)

        capfile = tmp_path / "addr.iv8cap"
        cap.save(capfile)

        loaded = PacketCapture.load(capfile)
        replay = loaded.replay()

        orig_src = sample_packets[0].src
        loaded_src = replay[0][1].src
        assert orig_src.to_int() == loaded_src.to_int()

    def test_empty_capture(self, tmp_path: Path) -> None:
        cap = PacketCapture()
        capfile = tmp_path / "empty.iv8cap"
        cap.save(capfile)

        loaded = PacketCapture.load(capfile)
        assert loaded.count == 0
        assert loaded.replay() == []

    def test_file_format(
        self, sample_packets: list[IPv8Packet], tmp_path: Path
    ) -> None:
        cap = PacketCapture()
        cap.start()
        cap.capture(sample_packets[0])

        capfile = tmp_path / "format.iv8cap"
        cap.save(capfile)

        lines = capfile.read_text().strip().split("\n")
        # First two lines are comments
        assert lines[0].startswith("#")
        assert lines[1].startswith("#")
        # Third line is data: timestamp hex
        parts = lines[2].split(" ", 1)
        assert len(parts) == 2
        int(parts[0])  # timestamp is parseable int
        bytes.fromhex(parts[1])  # hex is parseable
