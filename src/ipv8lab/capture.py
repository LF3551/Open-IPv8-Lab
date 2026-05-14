# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Packet capture and replay — save and replay IPv8 Lab packet traces.

Capture format (.iv8cap):
- Line-based text file
- Each line: timestamp_ns hex_encoded_packet
- Lines starting with # are comments
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from ipv8lab.packet import IPv8Packet


@dataclass(slots=True)
class CapturedPacket:
    """A single captured packet with a timestamp."""

    timestamp_ns: int
    packet: IPv8Packet


class PacketCapture:
    """Captures packets to a list and can save/load to .iv8cap files."""

    def __init__(self) -> None:
        self._packets: list[CapturedPacket] = []
        self._start_ns: int = 0

    def start(self) -> None:
        """Mark the start time of the capture."""
        self._start_ns = time.monotonic_ns()
        self._packets.clear()

    def capture(self, packet: IPv8Packet) -> None:
        """Record a packet with a relative timestamp."""
        ts = time.monotonic_ns() - self._start_ns if self._start_ns else 0
        self._packets.append(CapturedPacket(timestamp_ns=ts, packet=packet))

    @property
    def packets(self) -> list[CapturedPacket]:
        return list(self._packets)

    @property
    def count(self) -> int:
        return len(self._packets)

    def save(self, path: str | Path) -> None:
        """Save captured packets to a .iv8cap file."""
        with open(path, "w") as fh:
            fh.write("# IPv8 Lab Packet Capture\n")
            fh.write(f"# Packets: {self.count}\n")
            for cap in self._packets:
                raw = cap.packet.to_bytes()
                hex_data = raw.hex()
                fh.write(f"{cap.timestamp_ns} {hex_data}\n")

    @classmethod
    def load(cls, path: str | Path) -> "PacketCapture":
        """Load packets from a .iv8cap file."""
        cap = cls()
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(" ", 1)
                if len(parts) != 2:
                    continue
                ts_str, hex_data = parts
                ts = int(ts_str)
                raw = bytes.fromhex(hex_data)
                pkt = IPv8Packet.from_bytes(raw)
                cap._packets.append(CapturedPacket(timestamp_ns=ts, packet=pkt))
        return cap

    def replay(self) -> list[tuple[int, IPv8Packet]]:
        """Return packets in order with their timestamps for replay."""
        return [(cap.timestamp_ns, cap.packet) for cap in self._packets]
