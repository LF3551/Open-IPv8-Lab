# Roadmap

## v0.1 — Addressing core

- [x] IPv8Address class
- [x] ASN to prefix conversion
- [x] Prefix to ASN conversion
- [x] Address validation
- [x] CLI command: `ipv8lab addr`
- [x] Unit tests

## v0.2 — Packet format

- [x] IPv8 Lab packet structure
- [x] Packet serialization
- [x] Packet parsing
- [x] CRC32 checksum
- [x] CLI command: `ipv8lab packet`
- [x] Unit tests

## v0.3 — Routing simulator

- [x] Route table
- [x] Route lookup
- [x] YAML config loader
- [x] Simple routing simulation
- [x] CLI command: `ipv8lab route simulate`

## v0.4 — Local testbed

- [x] Node abstraction
- [x] Router abstraction
- [x] Two-ASN demo
- [x] Packet tracing
- [x] Example scenarios

## v0.5 — UDP transport experiment

- [x] UDP framing protocol (magic + length)
- [x] Async UDP transport (send/receive)
- [x] UDP node runner with forwarding
- [x] UDP network orchestrator
- [x] CLI command: `ipv8lab udp run`
- [x] UDP demo example
- [x] Unit tests (transport + UDP runner)

## v0.6 — Developer tooling

- [x] Packet hex dump utility (`ipv8lab packet dump`)
- [x] JSON output mode (`--json` flag)
- [x] Address summary JSON
- [x] Packet summary JSON
- [x] Mypy type checking in CI
- [x] More unit tests (dump, hexdump, summaries)

## v0.7 — Future ideas

- [ ] Multi-hop mesh topologies
- [ ] Packet capture/replay
- [ ] Web UI dashboard
- [ ] Performance benchmarks
- [ ] Plugin system for custom protocols
