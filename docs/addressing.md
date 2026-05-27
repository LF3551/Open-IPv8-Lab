[← Home](index.md)

# IPv8 Addressing (Sections 3, 4, 6)

Per draft-thain-ipv8 Sections 3–4 and 6.

## Address format (Section 3.1)

An IPv8 address is a 64-bit value consisting of a 32-bit **Routing Number (RN)**
and a 32-bit **Local Address (LA)**.

### Canonical hyphenated notation (Section 3.3)

```
<RN>-<LA>
```

- When the leading octet of RN is `0`, the RN renders as a plain integer
  (`ASN_SIMPLIFICATION=True`, the default).
- When the leading octet of RN is non-zero, the RN renders as a dotted quad.

Examples:

```
64496-192.0.2.1        (RN=64496, integer form; leading octet 0)
127.2.0.0-10.0.0.5    (RN=0x7F020000, dotted-quad form; leading octet 127)
```

### Legacy input forms (accepted but not emitted)

| Form | Example |
|------|---------|
| ASN dot notation | `64496-192.0.2.1` |
| Full 8-octet | `0.0.251.240.192.0.2.1` |

All three forms round-trip to the canonical hyphenated form on output.

### RN encoding (Section 3.4)

```
RN 64496 → 0x0000FBF0 → 0.0.251.240
```

## Address classes (Section 4)

| RN range | Class | Description |
|----------|-------|-------------|
| `0.0.0.0` | IPv4-Compatible | Route on LA using IPv4 rules |
| `0.0.0.1` – `99.255.255.255` | RN Unicast | Public internet routing via eBGP8 |
| `100.0.0.0/8` | RINE Peering | AS-to-AS peering links; MUST NOT be globally routed |
| `101.0.0.0` – `126.255.255.255` | RN Unicast | Public internet routing via eBGP8 |
| `127.0.0.0/8` | Internal Zone | MUST NOT be routed externally |
| `128.0.0.0` – `ff.fe.ff.ff` | RN Unicast | Public internet routing via eBGP8 |
| `ff.ff.00.00` – `ff.ff.ef.ff` | Cross-RN Multicast | Group assignments |
| `ff.ff.ff.ff` | Broadcast | Maps to L2 broadcast; MUST NOT be routed |

> **Note:** The `127.127.0.0` Inter-Company Interop Prefix has been removed from
> the spec. Use the two-XLATE8 model (`interop.py`) instead.

### Special conventions

- **Interior link** (Section 4.10): LA `222.0.0.0/8` — router-to-router links within an AS
- **Private peering RN** (Section 4.8): RN 65534 (`0.0.255.254`) — private inter-company BGP8
- **Documentation RN** (Section 4.8): RN 65533 (`0.0.255.253`) — testing purposes

## Validation rules

- All octets must be in range 0–255
- RN must be in range 0–4294967295
- LA must consist of exactly 4 octets
- Full address must consist of exactly 8 octets
- Internal zone addresses (127.x.x.x RN) MUST NOT appear on WAN interfaces
- RINE addresses (100.x.x.x RN) MUST NOT be assigned to end devices
