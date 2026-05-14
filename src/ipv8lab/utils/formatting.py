# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Formatting helpers."""


def dotted(octets: tuple[int, ...]) -> str:
    """Format a tuple of octets as a dotted string."""
    return ".".join(str(o) for o in octets)
