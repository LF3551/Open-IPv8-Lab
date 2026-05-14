# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Node abstraction for the IPv8 Lab network simulator."""

from __future__ import annotations

from dataclasses import dataclass, field

from ipv8lab.address import IPv8Address
from ipv8lab.packet import IPv8Packet
from ipv8lab.route import RouteTable


@dataclass(slots=True)
class Node:
    """A simulated network node (host or router)."""

    name: str
    address: IPv8Address
    routes: RouteTable = field(default_factory=RouteTable)
    inbox: list[IPv8Packet] = field(default_factory=list)
    outbox: list[IPv8Packet] = field(default_factory=list)

    @property
    def asn(self) -> int:
        return self.address.asn

    def send_packet(self, packet: IPv8Packet) -> None:
        self.outbox.append(packet)

    def receive_packet(self, packet: IPv8Packet) -> None:
        self.inbox.append(packet)
