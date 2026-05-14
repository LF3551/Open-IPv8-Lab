# Open-IPv8-Lab

<p align="center">
  <img src="assets/logo.png" alt="Open-IPv8-Lab" width="100%">
</p>

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![SPDX](https://img.shields.io/badge/SPDX-Apache--2.0-brightgreen.svg)](https://spdx.org/licenses/Apache-2.0.html)
[![Tests](https://github.com/LF3551/Open-IPv8-Lab/actions/workflows/tests.yml/badge.svg)](https://github.com/LF3551/Open-IPv8-Lab/actions/workflows/tests.yml)

Open-IPv8-Lab is an experimental userspace toolkit for exploring IPv8 concepts, including ASN-based addressing, packet encoding and decoding, routing simulation, and local multi-node testbed demos.

Created and maintained by Aleksei Aleinikov ([@LF3551](https://github.com/LF3551)).

## Status

> **This project is experimental and educational.** It is not an official IPv8 implementation, not an IETF standard implementation, and not production networking software.

## Goals

- Parse IPv8-style addresses
- Convert ASN values to 4-octet routing prefixes
- Build and parse experimental IPv8 Lab packets
- Simulate IPv8-style routing in userspace
- Provide local testbed demos
- Help researchers and developers explore IPv8 concepts safely

## Non-goals

- No Linux kernel modifications in the first version
- No production networking
- No real BGP integration
- No claim of official IPv8 compatibility
- No replacement for IPv4 or IPv6

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Quick start

```bash
# Parse an IPv8 address
ipv8lab addr parse 64496.192.0.2.1

# Convert ASN to routing prefix
ipv8lab addr encode-asn 64496

# Decode prefix back to ASN
ipv8lab addr decode-prefix 0.0.251.240

# Build a packet
ipv8lab packet build --src 64496.192.0.2.1 --dst 64497.198.51.100.7 --payload "hello"

# Parse a packet from file
ipv8lab packet parse packet.bin

# Run routing simulation
ipv8lab route simulate --config examples/two_asn_demo.yaml
```

## Example output

```
ipv8lab addr parse 64496.192.0.2.1

Input                64496.192.0.2.1
Format               ASN dot notation
ASN                  64496
Routing prefix       0.0.251.240
Host part            192.0.2.1
Full notation        0.0.251.240.192.0.2.1
```

## Testing

```bash
pytest -v
```

## Documentation

- [Overview](docs/overview.md)
- [Addressing](docs/addressing.md)
- [Packet format](docs/packet-format.md)
- [Routing simulator](docs/routing-simulator.md)
- [Testbed](docs/testbed.md)
- [Roadmap](docs/roadmap.md)

## License

This project is licensed under the [Apache License 2.0](LICENSE).

SPDX-License-Identifier: `Apache-2.0`

## Attribution

Use, modification, and distribution are permitted under the Apache License 2.0,
provided that the following conditions are met:

- The original copyright notice and license text must be preserved in all copies or substantial portions of the software.
- The [NOTICE](NOTICE) file must be included in any redistribution.
- Attribution to the original author — **Aleksei Aleinikov** ([@LF3551](https://github.com/LF3551)) — must remain intact.

If you use this project in your own work, please credit:

```
IPv8 Lab — Copyright 2026 Aleksei Aleinikov
https://github.com/LF3551/Open-IPv8-Lab
```
