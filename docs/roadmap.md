[← Home](index.md)

# Roadmap

## v0.1 — Addressing core

- [x] IPv8Address class
- [x] ASN to prefix conversion
- [x] Prefix to ASN conversion
- [x] Address validation
- [x] CLI command: `ipv8lab addr`

## v0.2 — Packet format

- [x] IPv8 Lab packet structure
- [x] Packet serialization
- [x] Packet parsing
- [x] CRC32 checksum
- [x] CLI command: `ipv8lab packet`

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

## v0.6 — Developer tooling

- [x] Packet hex dump utility (`ipv8lab packet dump`)
- [x] JSON output mode (`--json` flag)
- [x] Address summary JSON
- [x] Packet summary JSON
- [x] Mypy type checking in CI

## v0.7 — Mesh, capture, dashboard, benchmarks, plugins

- [x] Multi-hop mesh topologies with cycle detection
- [x] Packet capture/replay (.iv8cap format)
- [x] Web UI dashboard (dark theme, JSON API)
- [x] Performance benchmarks (6 benchmarks)
- [x] Plugin system for custom protocols
- [x] Error hierarchy (IPv8LabError)

## v0.8 — draft-thain-ipv8 spec compliance

- [x] Address class classification per Section 4
- [x] Spec-compliant packet header `!BBHHHBBHIIII` per Section 5.1
- [x] Prefix validation and routing scope per Sections 3.5, 3.9, 3.10
- [x] Two-tier routing table per Section 8.7
- [x] Multicast/broadcast classification per Sections 10–12
- [x] Border router ingress filtering per Section 18
- [x] ICMPv8 protocol per Section 9
- [x] 8to4 tunnelling per Section 13.3
- [x] Device compliance tiers per Sections 17.1–17.3
- [x] NIC rate limits per Section 17.5
- [x] DNS A8 record type per Section 7
- [x] VRF per Section 8.8
- [x] PVRST per Section 17.4

## v0.9 — Management suite & companion specs

- [x] Cost Factor (CF) metric simulation per Section 1.6
- [x] WHOIS8 mock resolver (ASN validation, route validation)
- [x] DHCP8 lease simulation per Section 1.3 (single-response provisioning)
- [x] Zone Server mock (OAuth8 cache, ACL8 engine) per Sections 1.3, 1.4
- [x] NetLog8 telemetry client (SEC-ALERT, E3 traps) per Section 18
- [x] Companion spec modules:
  - [x] BGP8/IBGP8/OSPF8/IS-IS8 (draft-thain-routing-protocols)
  - [x] RINE peering fabric (draft-thain-rine)
  - [x] ARP8 with gratuitous announce (draft-thain-support8)
  - [x] XLATE8 translation table (draft-thain-zoneserver)
  - [x] Update8 and NIC certification (draft-thain-update8)
  - [x] WiFi8 protocol (draft-thain-wifi8)
  - [x] SNMPv8 MIB (draft-thain-ipv8-mib)

## v0.10 — Integration scenarios

- [x] End-to-end integration scenario (DHCP8 → OAuth8 → ACL8 → routing)
- [x] Multi-zone simulation with Zone Server pairs
- [x] BGP8 path selection with CF metric
- [x] XLATE8 north-south traffic flow
- [x] Interactive CLI for Zone Server management (`ipv8lab zone`)
- [x] Multi-zone CLI commands (`ipv8lab multizone`)
- [x] BGP8 path selection CLI (`ipv8lab bgp8`)
- [x] XLATE8 flow CLI (`ipv8lab xlate8`)
- [x] Performance dashboard with CF visualisation (`ipv8lab cf`)
- [x] PCAP export for Wireshark integration (`ipv8lab pcap`)
- [x] IPv8 packet fragmentation and reassembly (`ipv8lab frag`)
- [x] Traceroute8 diagnostic utility (`ipv8lab traceroute`)

## v0.11 — Security, operations & tooling

- [x] NAT8 address translation gateway simulation (`ipv8lab nat8`)
- [x] Flow monitoring and NetFlow8-style telemetry export (`ipv8lab netflow8`)
- [x] QoS / traffic shaping based on TOS field (`ipv8lab qos`)
- [x] Docker-based multi-node testbed (`ipv8lab docker`)
- [x] TUI dashboard — Rich Live / Textual (`ipv8lab tui`)
- [x] Packet fuzzer for protocol security testing (`ipv8lab fuzz`)
- [x] mTLS / encryption layer for Zone Server auth (`ipv8lab mtls`)

## v0.12 — Full spec compliance & companion protocols

- [x] Interior Link Convention Protection (222.0.0.0/8 BGP8 filtering) per Section 19.4 (`ipv8lab ilinkprot`)
- [x] /16 Minimum Prefix Enforcement at eBGP8 boundaries per Section 19.7 (`ipv8lab prefixenf`)
- [x] Companion spec: draft-thain-whois8 — standalone WHOIS8 protocol (`ipv8lab whois8`)
- [x] Companion spec: draft-thain-netlog8 — standalone NetLog8 protocol (`ipv8lab netlog8proto`)

## Previously completed — draft-thain-ipv8 compliance

- [x] ARP8-driven version selection simulation per Section 2
- [x] Inter-Company Interop Prefix (127.127.0.0) and Two-XLATE8 Interop Model per Sections 4.6–4.7
- [x] Private Interop ASN (65534/65533) reservation per Section 4.8
- [x] Interior Link Convention (222.0.0.0/8) address validation per Section 4.10
- [x] Address Usage Model — consolidated address space table per Section 4.11
- [x] Socket API Compatibility mock (AF_INET8, sockaddr_in8) per Section 6.2
- [x] CGNAT Behaviour simulation (r.r.r.r preservation, n.n.n.n-only NAT) per Section 15
- [x] XLATE8 Even/Odd Load Balancing per Section 15.1
- [x] Cloud Provider VPC simulation (zone prefix → VPC mapping) per Section 17
- [x] RINE Prefix Protection (100.x.x.x filtering, SEC-ALERT) per Section 19.3

## v1.0 — draft-thain-ipv8 compliance (in progress, branch `spec/draft-thain-ipv8`)

The lab currently targets **draft-thain-ipv8**. Spec introduces the
canonical hyphenated locator `<RN>-<LA>`, formalises "RN is a fancy VRF" with
RD `<RN>:65535`, adds the per-segment-one-RN invariant, renames per-interface
modes, bumps `AF_INET8` from 30 to 46, registers EtherType `0x8080`, and drops
the `127.127.0.0/16` Inter-Company Interop Prefix. This section enumerates the
migration step-by-step, separating what changes from what stays.

### What stays unchanged (no work required)

- **Wire-level packet header layout.** `!BBHHHBBHIIII` = 28 bytes, Version=8,
  IHL=7, two 64-bit addresses inserted in place of IPv4's two 32-bit addresses.
  Spec §Header Format matches the existing format byte-for-byte; only field
  *names* change (RN/LA instead of ASN-prefix/host).
- **L4 transports.** TCP, UDP, QUIC, SCTP, ICMP, ARP remain single protocols
  with v8-extension behaviour. The suite explicitly disclaims "TCP8/UDP8" as
  separate protocols. No code rename required.
- **Routing-protocol names.** BGP8/IBGP8/OSPF8/IS-IS8 stay; they are
  extensions, not new protocols.
- **CRC32 / checksum, IPv4-Compatible Form (RN=0), fragmentation, MTU paths,
  Docker testbed, TUI/dashboard, PCAP export pipeline, Lua dissector skeleton,
  benchmark suite, fuzzer, mTLS, NetFlow8, QoS.** All carry over unchanged.
- **Reserved blocks `0`, `100`, `127`, `222`.** Semantics unchanged; only the
  framing changes from prefix-match (`127.0.0.0/8`) to categorical leading-
  octet match. Existing `address.py` already uses tuple-equality on the
  leading octet, so behaviour is correct — only docstrings need adjustment.

### Step 1 — Address rendering and parsing (`src/ipv8lab/address.py`)

- [x] Add hyphenated canonical form `<RN>-<LA>` as the **emit** default.
  - leading RN octet == 0 → integer (`64500-192.0.2.1`)
  - leading RN octet != 0 → dotted quad (`127.10.60.10-10.0.0.1`)
- [x] Add `IPv8Address.parse()` accepting **all three** forms on input:
  hyphenated (new canonical), `R.R.R.R.n.n.n.n` (legacy 8-octet), and
  `ASN.n.n.n.n` (legacy dot-ASN). Round-trip emits hyphenated.
- [x] Add module-level config flag `ASN_SIMPLIFICATION` (default `True`) per
  spec §3.5. When `False`, RN always renders as dotted quad regardless of
  leading octet. Wire/JSON encoding unaffected.
- [x] Rename properties for spec alignment, keep old as aliases:
  `routing_prefix` → `rn_octets` (alias kept), `host_part` → `la_octets`
  (alias kept), `asn` → `rn` (alias kept), `full_notation` →
  `dotted_notation`, add new `canonical` returning the hyphenated form.
- [x] Reject prefix lengths `>32` and any notation that implies subnetting
  across the RN boundary (spec §3.3).

### Step 2 — Reserved block table (`src/ipv8lab/address.py`, `interop.py`)

- [x] Mark `is_interop_prefix()` (`127.127.0.0`) and the whole `interop.py`
  module as **deprecated** with `DeprecationWarning`. Spec removes the
  Inter-Company Interop Prefix; replaced by the general two-XLATE8 model in
  `[@ZONESERVER]`.
- [x] Add new classification helpers per spec §4.4 table:
  - `is_super_scalar()` — leading octet 1–32
  - `is_rir_sub_rn()` with `rir` property returning `ARIN|RIPE|APNIC|LACNIC|AFRINIC`
    for octets 110–119
  - `is_cellular_carrier()` — leading octet 128–130
  - `is_iana_reserved()` — the gaps 33–99, 101–109, 120–126, 131–221, 223–255
- [x] Update existing helpers' docstrings to spec section refs.

### Step 3 — Socket API (`src/ipv8lab/socket_api.py`)

- [x] **Bump `AF_INET8` from 30 → 46** (spec §6 Socket API Compatibility).
- [x] Rename `SockaddrIn8.sin8_asn` → `sin8_rn` (alias kept). Keep
  `to_ipv8_address()` behaviour.
- [x] Add note: this is a userspace mock; the Linux kernel reference value
  (46) is provisional pending IANA assignment.
- [x] Update `tests/test_socket_api.py` to assert the new constant.

### Step 4 — Per-interface mode (`src/ipv8lab/dhcp8.py`, new `interface_mode.py`)

- [x] Define `InterfaceMode` enum: `NORMAL | STRICT | PNP | GUEST` per
  spec §7.7.1. Rename any historical `PRINTER` → `PNP` with backwards alias.
- [x] Add **DHCP8 option 222** (Primary RN, 32-bit) and **option 223**
  (interface mode, 1 byte) to `DHCP8Lease` and the offer builder.
- [x] Enforce "mode is immutable per session" — changing mode requires
  interface reset. Add an `Interface.reset_to_mode()` helper that bumps
  session id.
- [x] **Strict mode** behaviour: maintain a per-interface DNS resolution
  cache; reject outbound packets to destinations without a recent (TTL)
  DNS resolution. Emit NetLog8 `E`-class event on rejection.
- [x] **PNP mode**: register published service multicast groups with the
  segment's ACL server; permit mDNS/SSDP/WS-Discovery/LLMNR.
- [x] **Guest mode**: deny destinations in any RN other than 0 (public
  IPv4 internet) and registered PNP services on the segment.

### Step 5 — Per-segment RN invariant (`src/ipv8lab/compliance.py`, `arp8_version.py`)

- [x] Add `Segment` abstraction with single `primary_rn` field.
- [x] At config-commit time, validate:
  - every IPv4 address on every interface on the segment has the
    segment's primary RN as its RN context
  - every IPv8-aware interface's **Primary** IPv8 address is in the same RN
  - any number of **Secondary** IPv8 addresses MAY exist in other RNs
- [x] Extend `arp8_version.py` into **ARP8 Primary RN Discovery**: detect
  runtime conflicts (neighbour announcing a different Primary RN on the
  same segment). On conflict:
  - emit `NetLog8 SEC-ALERT`
  - refuse forwarding on the affected interface until resolved
- [x] Add `tests/test_segment_invariant.py`.

### Step 6 — RN-as-VRF naming convention (`src/ipv8lab/vrf.py`, `route.py`)

- [x] Auto-name VRFs `ipv8-asn-<RN>` with RD `<RN>:65535` whenever an RN is
  first bound to an interface (§3.2 "Adding an RN to an Interface").
- [x] Implement **"hosts only the RNs it advertises"** rule: a router keeps
  a local VRF only for RNs whose routes it originates/terminates. Transit
  RNs live in the RIB (`route.py`) but have no forwarding context — next
  hop comes from BGP8 attribute, not from a local VRF lookup.
- [x] Add **two-paths-to-the-internet** behaviour for hosts with multiple
  RN bindings: default-route selection by RN context, with Primary RN's
  gateway as the fall-through.

### Step 7 — Wire format selection (`src/ipv8lab/pcap_export.py`, `transport.py`)

- [x] Register EtherType `0x8080` (`ETH_P_IPV8`) for native IPv8 frames.
- [x] Per-packet wire-format decision (spec §5.2):
  - `ETH_P_IP` when destination is reached at the segment's Primary RN
    (covers all IPv4-only-to-IPv4-only traffic and Primary↔Primary IPv8)
  - `ETH_P_IPV8` when destination RN ≠ segment's Primary RN (cross-RN
    or peer's Secondary RN identity on the same segment)
- [x] Update Lua dissector `ipv8_dissector.lua` to register on EtherType
  `0x8080`. Keep IPIP/IP-proto-IPv8 path for 8-over-4 encapsulation.
- [x] Update `examples/packet_demo.py` to demonstrate both framings.

### Step 8 — XLATE8 unified subsystem (`src/ipv8lab/xlate8_flow.py`, `xlate8_lb.py`)

- [x] Merge `xlate8_flow.py` + `xlate8_lb.py` into a single `xlate8.py` with
  one state-table substrate and four selectable modes per spec §Terminology:
  1. **native IPv8 forwarding**
  2. **4-to-8 translation** (IPv4-only host → IPv8 boundary)
  3. **8-to-4 translation** (IPv8 → IPv4-only destination)
  4. **8-to-8 NAPT** between RN namespaces
  5. **8-over-IPv4 encapsulation** for IPv4-only transit
- [x] Even/odd `.254`/`.253` load-balancing is preserved as a deployment
  pattern of mode 1 + mode 5, not as a separate subsystem.

### Step 9 — DNS discovery (`src/ipv8lab/dns_a8.py`)

- [x] Add **ZS resource record type** (MX-style preference + target FQDN),
  in addition to existing A8.
- [x] Implement the spec §3.4 lookup order:
  1. ZS RRset under `<RN>.asn.arpa` (preferred), MX-style sort by preference
  2. Parallel `<RN>.asn.openipv8.org` for hosted/private/experimental
  3. Fallback to `anycast.<RN>.asn.arpa` as an ordinary A record
- [x] Add `examples/dns_discovery_demo.py`.

### Step 10 — Inter-AS routing propagation (`src/ipv8lab/bgp8_selection.py`)

- [x] Model all three propagation mechanisms per spec §"Inter-AS Routing
  Mechanisms":
  1. **Native BGP8** — MP-BGP NLRI with IPv8 AFI, full 64-bit `<RN>-<LA>`
  2. **BGP-in-VRF** — VPNv4 [RFC 4364] inside `ipv8-asn-<RN>` VRF
  3. **`asn-ibgp-path` large community** — 32-bit IPv4 NLRI + BGP large
     community [RFC 8092] carrying RN; receivers reconstruct full prefix
- [x] Add per-session capability negotiation; ensure the three paths
  produce **functionally identical** Route8 RIB entries.

### Step 11 — Cost Factor scope tightening (`src/ipv8lab/cost_factor.py`)

- [x] Restrict CF carriage to **inter-AS BGP8 path attributes only**.
- [x] Add the **IGP CF Export Interface**: collect OSPF/IS-IS/IBGP metrics
  intra-AS and surface them as CF inputs to IBGP8 — without overriding
  the IGP's native path selection inside the AS.
- [x] Implement slow-slew adjustment so CF doesn't induce route flap.

### Step 12 — Trust-state update discipline (`src/ipv8lab/mtls.py`, `whois8.py`, `rine_protection.py`)

- [x] For every trust store (AnycastROA filter, WHOIS8 cert trust, RIR
  anchors, RINE region membership, Sun Tzu baseline) implement two
  **separate** operator commands:
  - `verify` — diff upstream vs local, no modification
  - `update` — install upstream
- [x] Emit console warning when local trust state hasn't been refreshed
  for ≥ 7 days (configurable).
- [x] Retain previous N versions of trust state for rollback.

### Step 13 — Identity-Driven Access Control (`src/ipv8lab/zoneserver.py`)

- [x] Formalise OAuth8/JWT as the AAA substrate; ACL8 evaluates JWT
  claims per access decision, not 802.1X port state.
- [x] **NetLog8 silence on routine JWT presentations** — log only JWT
  issuance at session start and explicit failures. Add a regression
  test that asserts NetLog8 does not emit on a successful JWT check.

### Step 14 — Documentation, examples, README

- [x] Update README: change all locator examples from `64496-192.0.2.1` to
  `64496-192.0.2.1`. Add note that legacy notation is accepted on input.
- [x] Rewrite `examples/address_examples.txt` in hyphenated form.
- [x] Update `docs/addressing.md`, `docs/packet-format.md`,
  `docs/architecture.md` with spec section references.
- [x] Add `docs/spec-coverage.md` table mapping each spec section to
  the lab module(s) implementing it.
- [x] Update `docs/architecture.md` with the §"An RN is a Fancy VRF"
  framing and a callout that union-on-`iphdr` is **not** the model.

### Step 15 — CI, version bumps, release

- [ ] Bump `pyproject.toml` version to `1.0.0`.
- [ ] Add `tests/test_addr_canonical.py` covering all three input forms
  and the `asn-simplification` toggle.
- [ ] Update `test_arp8_version.py` to assert ARP8 Primary RN Discovery.
- [ ] Run full test suite; target zero regressions on the existing 1827
  tests plus the new spec cases.
- [ ] Update `CHANGELOG.md` with a `[1.0.0]` entry summarising the spec
  migration.

