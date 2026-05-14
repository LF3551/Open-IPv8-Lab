# IPv8 Addressing

## Address formats

### Full 8-octet notation

```
r.r.r.r.n.n.n.n
```

- `r.r.r.r` — routing prefix (4 octets)
- `n.n.n.n` — host part (4 octets)

Example: `0.0.251.240.192.0.2.1`

### ASN dot notation

```
ASN.n.n.n.n
```

- `ASN` — Autonomous System Number (32-bit integer)
- `n.n.n.n` — host part (4 octets)

Example: `64496.192.0.2.1`

The ASN is converted to a 4-octet routing prefix:

```
ASN 64496 → 0x0000FBF0 → 0.0.251.240
```

## Special address types

### IPv4-compatible address

Routing prefix is `0.0.0.0`:

```
0.0.0.0.8.8.8.8
```

### Internal zone address

First octet of routing prefix is `127`:

```
127.2.0.0.10.0.0.5
```

## Validation rules

- All octets must be in range 0–255
- ASN must be in range 0–4294967295
- Host part must consist of exactly 4 octets
- Full address must consist of exactly 8 octets
- ASN dot notation must consist of ASN + 4 octets
