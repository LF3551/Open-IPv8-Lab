# Open-IPv8-Lab

<p align="center">
  <img src="https://raw.githubusercontent.com/LF3551/Open-IPv8-Lab/main/assets/logo.png" alt="Open-IPv8-Lab" width="100%">
</p>

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://github.com/LF3551/Open-IPv8-Lab/blob/main/LICENSE)
[![SPDX](https://img.shields.io/badge/SPDX-Apache--2.0-brightgreen.svg)](https://spdx.org/licenses/Apache-2.0.html)
[![Tests](https://github.com/LF3551/Open-IPv8-Lab/actions/workflows/tests.yml/badge.svg)](https://github.com/LF3551/Open-IPv8-Lab/actions/workflows/tests.yml)
[![PyPI](https://img.shields.io/pypi/v/open-ipv8-lab.svg)](https://pypi.org/project/open-ipv8-lab/)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.20201237.svg)](https://doi.org/10.5281/zenodo.20201237)

Experimental userspace toolkit implementing [draft-thain-ipv8](https://www.ietf.org/archive/id/draft-thain-ipv8.html) — the Internet Protocol Version 8 specification.

!!! note "Educational project"
    Not an official IPv8 implementation, not production networking software.

Created and maintained by **Aleksei Aleinikov** ([@LF3551](https://github.com/LF3551)).

---

## Quick Start

```bash
pip install open-ipv8-lab

# Parse an IPv8 address
ipv8lab addr parse 64496-192.0.2.1

# Build a packet
ipv8lab packet build --src 64496-192.0.2.1 --dst 64497-198.51.100.7 --payload "hello"

# Routing simulation
ipv8lab route simulate --config examples/two_asn_demo.yaml
```

See [Examples](examples.md) for 10 step-by-step walkthroughs.

---

## Features at a Glance

- **Core Protocol Stack** — 64-bit addressing, 28-byte header, fragmentation, two-tier routing, ICMPv8
- **Zone Server** — OAuth8, ACL8, DHCP8, multi-zone simulation, mTLS
- **Routing & Traffic** — BGP8, Cost Factor, XLATE8, NAT8, CGNAT, ARP8
- **Security** — RINE prefix protection, interior link protection, prefix enforcement
- **Companion Protocols** — WHOIS8, NetLog8, OSPF8, IS-IS8, WiFi8, SNMPv8
- **Tooling** — PCAP export, traceroute8, fuzzer, TUI dashboard, benchmarks

Browse the full [CLI Reference](cli-reference.md) for all 35 commands.

---

## License

[Apache License 2.0](https://github.com/LF3551/Open-IPv8-Lab/blob/main/LICENSE) · SPDX: `Apache-2.0`
