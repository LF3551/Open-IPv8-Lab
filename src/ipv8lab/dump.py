# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Packet dump and hex-display utilities."""

from __future__ import annotations

from ipv8lab.packet import IPv8Packet


def hexdump(data: bytes, width: int = 16) -> str:
    """Return a classic hex dump string of *data*."""
    lines: list[str] = []
    for offset in range(0, len(data), width):
        chunk = data[offset : offset + width]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset:08X}  {hex_part:<{width * 3 - 1}}  |{ascii_part}|")
    return "\n".join(lines)


def packet_summary(pkt: IPv8Packet) -> dict:
    """Return a dict summary of a packet (for JSON output)."""
    return {
        "version": pkt.version,
        "ttl": pkt.ttl,
        "protocol": pkt.protocol,
        "flags": pkt.flags,
        "src": pkt.src.full_notation,
        "src_asn": pkt.src.asn,
        "dst": pkt.dst.full_notation,
        "dst_asn": pkt.dst.asn,
        "payload_length": len(pkt.payload),
        "checksum": f"0x{pkt.checksum:08X}",
        "payload_text": pkt.payload.decode(errors="replace"),
    }


def address_summary(addr_str: str) -> dict:
    """Return a dict summary of a parsed address (for JSON output)."""
    from ipv8lab.address import IPv8Address

    addr = IPv8Address.parse(addr_str)
    parts = addr_str.strip().split(".")
    fmt = "ASN dot notation" if len(parts) == 5 else "Full 8-octet notation"
    result = {
        "input": addr_str,
        "format": fmt,
        "asn": addr.asn,
        "routing_prefix": addr.prefix_str,
        "host_part": addr.host_str,
        "full_notation": addr.full_notation,
    }
    if addr.is_ipv4_compatible():
        result["type"] = "IPv4-compatible"
    elif addr.is_internal_zone():
        result["type"] = "Internal zone"
    return result
