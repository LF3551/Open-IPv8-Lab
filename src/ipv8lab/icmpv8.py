# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""ICMPv8 protocol per draft-thain-ipv8-00 Section 9.

ICMPv8 extends ICMP to support 64-bit IPv8 addresses.
Supported message types:
- Echo Request / Echo Reply
- Destination Unreachable
- Time Exceeded
- Redirect
- Parameter Problem

All messages carry full 64-bit source and destination addresses.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum

from ipv8lab.address import IPv8Address


class ICMPv8Type(IntEnum):
    """ICMPv8 message types (aligned with ICMPv4 numbering)."""

    ECHO_REPLY = 0
    DESTINATION_UNREACHABLE = 3
    REDIRECT = 5
    ECHO_REQUEST = 8
    TIME_EXCEEDED = 11
    PARAMETER_PROBLEM = 12


class UnreachableCode(IntEnum):
    """Destination Unreachable codes."""

    NET_UNREACHABLE = 0
    HOST_UNREACHABLE = 1
    PROTOCOL_UNREACHABLE = 2
    PORT_UNREACHABLE = 3
    FRAGMENTATION_NEEDED = 4
    SOURCE_ROUTE_FAILED = 5
    ASN_UNREACHABLE = 6  # IPv8-specific: no route to ASN prefix


class TimeExceededCode(IntEnum):
    """Time Exceeded codes."""

    TTL_EXCEEDED = 0
    FRAGMENT_REASSEMBLY = 1


class RedirectCode(IntEnum):
    """Redirect codes."""

    NETWORK = 0
    HOST = 1
    TOS_NETWORK = 2
    TOS_HOST = 3


# ICMPv8 header: type(1) + code(1) + checksum(2) + identifier(2) + sequence(2) = 8 bytes
ICMPV8_HEADER_FMT = "!BBHHH"
ICMPV8_HEADER_SIZE = struct.calcsize(ICMPV8_HEADER_FMT)  # 8 bytes


@dataclass(slots=True)
class ICMPv8Message:
    """An ICMPv8 message with full 64-bit addressing."""

    msg_type: ICMPv8Type
    code: int
    src: IPv8Address
    dst: IPv8Address
    identifier: int = 0
    sequence: int = 0
    payload: bytes = b""

    def to_bytes(self) -> bytes:
        """Serialize the ICMPv8 message."""
        header_no_cksum = struct.pack(
            ICMPV8_HEADER_FMT,
            self.msg_type,
            self.code,
            0,  # checksum placeholder
            self.identifier,
            self.sequence,
        )
        data = header_no_cksum + self.payload
        cksum = _internet_checksum(data)
        header = struct.pack(
            ICMPV8_HEADER_FMT,
            self.msg_type,
            self.code,
            cksum,
            self.identifier,
            self.sequence,
        )
        return header + self.payload

    @classmethod
    def from_bytes(
        cls,
        data: bytes,
        src: IPv8Address,
        dst: IPv8Address,
        *,
        verify: bool = True,
    ) -> "ICMPv8Message":
        """Deserialize an ICMPv8 message."""
        if len(data) < ICMPV8_HEADER_SIZE:
            msg = f"ICMPv8 too short: {len(data)} bytes, need {ICMPV8_HEADER_SIZE}"
            raise ValueError(msg)

        msg_type_raw, code, checksum, identifier, sequence = struct.unpack(
            ICMPV8_HEADER_FMT, data[:ICMPV8_HEADER_SIZE]
        )

        if verify:
            check_data = struct.pack(
                ICMPV8_HEADER_FMT, msg_type_raw, code, 0, identifier, sequence
            ) + data[ICMPV8_HEADER_SIZE:]
            if _internet_checksum(check_data) != checksum:
                msg = "ICMPv8 checksum mismatch"
                raise ValueError(msg)

        return cls(
            msg_type=ICMPv8Type(msg_type_raw),
            code=code,
            src=src,
            dst=dst,
            identifier=identifier,
            sequence=sequence,
            payload=data[ICMPV8_HEADER_SIZE:],
        )


def _internet_checksum(data: bytes) -> int:
    """One's complement checksum (RFC 1071 style)."""
    if len(data) % 2:
        data = data + b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


# --- convenience constructors ------------------------------------------------


def echo_request(
    src: IPv8Address,
    dst: IPv8Address,
    identifier: int = 1,
    sequence: int = 1,
    payload: bytes = b"",
) -> ICMPv8Message:
    """Create an Echo Request message."""
    return ICMPv8Message(
        msg_type=ICMPv8Type.ECHO_REQUEST,
        code=0,
        src=src,
        dst=dst,
        identifier=identifier,
        sequence=sequence,
        payload=payload,
    )


def echo_reply(request: ICMPv8Message) -> ICMPv8Message:
    """Create an Echo Reply from a request (swap src/dst)."""
    return ICMPv8Message(
        msg_type=ICMPv8Type.ECHO_REPLY,
        code=0,
        src=request.dst,
        dst=request.src,
        identifier=request.identifier,
        sequence=request.sequence,
        payload=request.payload,
    )


def destination_unreachable(
    src: IPv8Address,
    dst: IPv8Address,
    code: UnreachableCode = UnreachableCode.NET_UNREACHABLE,
    payload: bytes = b"",
) -> ICMPv8Message:
    """Create a Destination Unreachable message."""
    return ICMPv8Message(
        msg_type=ICMPv8Type.DESTINATION_UNREACHABLE,
        code=code,
        src=src,
        dst=dst,
        payload=payload,
    )


def time_exceeded(
    src: IPv8Address,
    dst: IPv8Address,
    code: TimeExceededCode = TimeExceededCode.TTL_EXCEEDED,
    payload: bytes = b"",
) -> ICMPv8Message:
    """Create a Time Exceeded message."""
    return ICMPv8Message(
        msg_type=ICMPv8Type.TIME_EXCEEDED,
        code=code,
        src=src,
        dst=dst,
        payload=payload,
    )


def redirect(
    src: IPv8Address,
    dst: IPv8Address,
    code: RedirectCode = RedirectCode.NETWORK,
    payload: bytes = b"",
) -> ICMPv8Message:
    """Create a Redirect message."""
    return ICMPv8Message(
        msg_type=ICMPv8Type.REDIRECT,
        code=code,
        src=src,
        dst=dst,
        payload=payload,
    )
