[← Home](index.md)

# IPv8 Packet Header (Section 5.1)

Per draft-thain-ipv8 Section 5.1.

## Header format

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|         Total Length          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |         Header Checksum       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Source Routing Number (RN)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Source Local Address  (LA)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Destination Routing Number (RN)               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Destination Local Address  (LA)               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

## Header fields

| Field | Size | Description |
|-------|------|-------------|
| Version | 4 bits | IP version number: **8** |
| IHL | 4 bits | Internet Header Length (7 = 28 bytes) |
| Type of Service | 1 byte | TOS / DSCP |
| Total Length | 2 bytes | Header + payload |
| Identification | 2 bytes | Fragment identification |
| Flags | 3 bits | Fragmentation flags |
| Fragment Offset | 13 bits | Fragment offset |
| Time to Live | 1 byte | TTL hop count |
| Protocol | 1 byte | Upper-layer protocol |
| Header Checksum | 2 bytes | CRC32 truncated to 16 bits |
| Source RN | 4 bytes | Routing Number of source (§3.1) |
| Source LA | 4 bytes | Local Address of source (§3.1) |
| Dest RN | 4 bytes | Routing Number of destination (§3.1) |
| Dest LA | 4 bytes | Local Address of destination (§3.1) |

**Total header size: 28 bytes** (8 octets longer than IPv4)

**Wire format:** `!BBHHHBBHIIII`

## Checksum

CRC32 computed over header (with checksum field set to 0) + payload, truncated to 16 bits (`crc32 & 0xFFFF`).

## ICMPv8 (Section 9)

ICMPv8 extends ICMP for 64-bit addresses. Message types:

| Type | Name |
|------|------|
| 0 | Echo Reply |
| 3 | Destination Unreachable (incl. ASN_UNREACHABLE) |
| 5 | Redirect |
| 8 | Echo Request |
| 11 | Time Exceeded |
| 12 | Parameter Problem |

ICMPv8 uses one's complement checksum (RFC 1071). Header: `!BBHHH` (8 bytes).
