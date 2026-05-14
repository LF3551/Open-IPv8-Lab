# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for ipv8lab.checksum."""

from ipv8lab.checksum import crc32_checksum, verify_checksum


def test_crc32_deterministic():
    data = b"hello world"
    assert crc32_checksum(data) == crc32_checksum(data)


def test_crc32_different_data():
    assert crc32_checksum(b"aaa") != crc32_checksum(b"bbb")


def test_verify_checksum_ok():
    data = b"test payload"
    cksum = crc32_checksum(data)
    assert verify_checksum(data, cksum)


def test_verify_checksum_fail():
    assert not verify_checksum(b"test", 0xDEADBEEF)


def test_crc32_empty():
    assert crc32_checksum(b"") == 0
