[← Back to README](../README.md)

# IPv8 Addressing (Sections 3, 4, 6)

Per [draft-thain-ipv8-02](https://www.ietf.org/archive/id/draft-thain-ipv8-02.html) Sections 3–4 and 6.

## Address format (Section 3.1)

An IPv8 address is a 64-bit value:

### Full 8-octet notation

```
r.r.r.r.n.n.n.n
```

- `r.r.r.r` — 32-bit ASN Routing Prefix
- `n.n.n.n` — 32-bit Host Address (identical semantics to IPv4)

Example: `0.0.251.240.192.0.2.1`

### ASN dot notation (Section 6)

```
ASN.n.n.n.n
```

Example: `64496.192.0.2.1` = `0.0.251.240.192.0.2.1`

The ASN is encoded as a 32-bit unsigned integer in network byte order (Section 3.4):

```
ASN 64496 → 0x0000FBF0 → 0.0.251.240
```

## Address classes (Section 4)

| r.r.r.r range | Class | Description |
|----------------|-------|-------------|
| `0.0.0.0` | IPv4 Compatible | Route on n.n.n.n using IPv4 rules |
| `0.0.0.1` – `99.255.255.255` | ASN Unicast | Public internet routing via eBGP8 |
| `100.0.0.0/8` | RINE Peering | AS-to-AS peering links; MUST NOT be globally routed |
| `101.0.0.0` – `126.255.255.255` | ASN Unicast | Public internet routing via eBGP8 |
| `127.0.0.0/8` | Internal Zone | MUST NOT be routed externally |
| `127.127.0.0` | Interop Prefix | Inter-company DMZ |
| `128.0.0.0` – `ff.fe.ff.ff` | ASN Unicast | Public internet routing via eBGP8 |
| `ff.ff.00.00` – `ff.ff.ef.ff` | Cross-ASN Multicast | Group assignments |
| `ff.ff.ff.ff` | Broadcast | Maps to L2 broadcast; MUST NOT be routed |

### Special conventions

- **Interior link** (Section 3.10): n.n.n.n `222.0.0.0/8` — router-to-router links within an AS
- **Private peering ASN** (Section 3.8): ASN 65534 (`0.0.255.254`) — private inter-company BGP8
- **Documentation ASN** (Section 3.8): ASN 65533 (`0.0.255.253`) — testing purposes

## Validation rules

- All octets must be in range 0–255
- ASN must be in range 0–4294967295
- Host part must consist of exactly 4 octets
- Full address must consist of exactly 8 octets
- ASN dot notation must consist of ASN + 4 octets
- Internal zone addresses (127.x.x.x) MUST NOT appear on WAN interfaces
- RINE addresses (100.x.x.x) MUST NOT be assigned to end devices
