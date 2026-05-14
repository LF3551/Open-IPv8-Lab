# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Custom exception types for ipv8lab."""


class IPv8LabError(Exception):
    """Base exception for all ipv8lab errors."""


class InvalidAddressError(IPv8LabError):
    """Raised when an IPv8 address cannot be parsed or is invalid."""


class InvalidASNError(IPv8LabError):
    """Raised when an ASN value is out of range."""


class InvalidOctetError(IPv8LabError):
    """Raised when an octet value is out of range 0-255."""


class InvalidPacketError(IPv8LabError):
    """Raised when a packet cannot be parsed."""


class ChecksumMismatchError(IPv8LabError):
    """Raised when a packet checksum does not match."""


class NoRouteFoundError(IPv8LabError):
    """Raised when no matching route is found in the route table."""
