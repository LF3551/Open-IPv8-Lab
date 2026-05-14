# IPv8 Lab Packet Format

> **Note:** This is an internal experimental format for educational purposes.
> It is **not** an official IPv8 wire format or an IETF standard.

## Header fields

| Field          | Type   | Size    | Description                          |
|----------------|--------|---------|--------------------------------------|
| version        | uint8  | 1 byte  | Packet format version (currently 1)  |
| ttl            | uint8  | 1 byte  | Time to live                         |
| protocol       | uint8  | 1 byte  | Protocol identifier                  |
| flags          | uint8  | 1 byte  | Reserved flags                       |
| src_address    | uint64 | 8 bytes | Source IPv8 address                  |
| dst_address    | uint64 | 8 bytes | Destination IPv8 address             |
| payload_length | uint32 | 4 bytes | Length of payload in bytes            |
| checksum       | uint32 | 4 bytes | CRC32 of header (with cksum=0) + payload |

**Total header size: 28 bytes**

## Protocol values

| Value | Meaning                  |
|-------|--------------------------|
| 1     | ICMP-like control message|
| 6     | TCP-like payload         |
| 17    | UDP-like payload         |
| 253   | Experimental             |

For MVP, protocol 253 (experimental) is used by default.

## Checksum

CRC32 computed over:
1. Header with checksum field set to 0
2. Payload bytes

Concatenated and passed through `zlib.crc32()`.
