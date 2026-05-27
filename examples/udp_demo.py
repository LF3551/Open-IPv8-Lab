#!/usr/bin/env python3
# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""UDP transport demo — nodes communicate over real UDP sockets on localhost."""

import asyncio
import logging
from pathlib import Path

from ipv8lab.udp_runner import UDPNetwork

logging.basicConfig(level=logging.INFO, format="%(message)s")


async def main() -> None:
    config = Path(__file__).parent / "two_asn_demo.yaml"
    net = UDPNetwork.from_yaml(config)

    await net.start_all()

    # Show ports
    for name, unode in net.nodes.items():
        role = "router" if unode.is_router else "host"
        print(f"  {name} ({role}): 127.0.0.1:{unode.endpoint.port}")

    print()

    try:
        trace = await net.send_and_wait(
            "node-a",
            "64497-198.51.100.7",
            "hello via UDP!",
        )
        print("Trace:")
        for line in trace:
            print(f"  {line}")
    finally:
        net.stop_all()


if __name__ == "__main__":
    asyncio.run(main())
