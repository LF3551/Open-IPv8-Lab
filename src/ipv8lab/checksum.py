# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""CRC32-based checksum utilities for IPv8 Lab packets."""

import zlib


def crc32_checksum(data: bytes) -> int:
    """Return an unsigned CRC32 checksum of *data*."""
    return zlib.crc32(data) & 0xFFFFFFFF


def verify_checksum(data: bytes, expected: int) -> bool:
    """Return True if the CRC32 of *data* matches *expected*."""
    return crc32_checksum(data) == expected
