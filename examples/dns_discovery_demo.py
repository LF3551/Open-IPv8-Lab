#!/usr/bin/env python3
# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Zone Server discovery demo (spec §3.4 lookup order).

Demonstrates the three-step ZS lookup sequence:

  1. ZS RRset under ``<RN>.asn.arpa.``   — primary (preferred)
  2. ZS RRset under ``<RN>.asn.openipv8.org.`` — secondary
  3. A8 record at ``anycast.<RN>.asn.arpa.`` — anycast fallback
"""

from __future__ import annotations

from ipv8lab.address import IPv8Address
from ipv8lab.dns_a8 import A8Record, ZSRecord, ZSResolver, format_zs_zone_line


def _section(title: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print('=' * 60)


def demo_primary_lookup() -> None:
    _section("Step 1: primary lookup via <RN>.asn.arpa.")
    resolver = ZSResolver()
    rn = 64496

    resolver.add_zs(ZSRecord(f"{rn}.asn.arpa.", preference=10, target="zs1.example.com."))
    resolver.add_zs(ZSRecord(f"{rn}.asn.arpa.", preference=20, target="zs2.example.com."))

    print(f"Zone file entries for RN {rn}:")
    for rec in [
        ZSRecord(f"{rn}.asn.arpa.", preference=10, target="zs1.example.com."),
        ZSRecord(f"{rn}.asn.arpa.", preference=20, target="zs2.example.com."),
    ]:
        print(f"  {format_zs_zone_line(rec)}")

    result = resolver.lookup(rn)
    print(f"\nLookup RN={rn}:")
    print(f"  source  : {result.source}")
    print(f"  targets : {result.targets}")


def demo_secondary_fallback() -> None:
    _section("Step 2: secondary fallback via <RN>.asn.openipv8.org.")
    resolver = ZSResolver()
    rn = 64497

    # No asn.arpa records — falls through to openipv8.org
    resolver.add_zs(ZSRecord(f"{rn}.asn.openipv8.org.", preference=10, target="zs.openipv8.org."))

    result = resolver.lookup(rn)
    print(f"Lookup RN={rn} (no asn.arpa, has openipv8.org):")
    print(f"  source  : {result.source}")
    print(f"  targets : {result.targets}")


def demo_anycast_fallback() -> None:
    _section("Step 3: anycast fallback via anycast.<RN>.asn.arpa.")
    resolver = ZSResolver()
    rn = 64498

    # No ZS records at all — anycast A8 record only
    anycast_addr = IPv8Address.parse(f"{rn}-10.0.0.254")
    resolver.add_a8(A8Record(name=f"anycast.{rn}.asn.arpa.", address=anycast_addr))

    result = resolver.lookup(rn)
    print(f"Lookup RN={rn} (no ZS records, anycast only):")
    print(f"  source  : {result.source}")
    print(f"  targets : {result.targets}")


def demo_no_records() -> None:
    _section("No records — lookup returns 'none'")
    resolver = ZSResolver()
    result = resolver.lookup(65000)
    print(f"Lookup RN=65000:")
    print(f"  source  : {result.source}")
    print(f"  targets : {result.targets}")


def demo_precedence() -> None:
    _section("Precedence: primary beats secondary beats anycast")
    resolver = ZSResolver()
    rn = 64499

    # All three tiers present
    resolver.add_zs(ZSRecord(f"{rn}.asn.arpa.", preference=10, target="primary.zs.example.com."))
    resolver.add_zs(ZSRecord(f"{rn}.asn.openipv8.org.", preference=5, target="secondary.zs.example.com."))
    resolver.add_a8(A8Record(name=f"anycast.{rn}.asn.arpa.", address=IPv8Address.parse(f"{rn}-10.0.0.254")))

    result = resolver.lookup(rn)
    print(f"Lookup RN={rn} (all 3 tiers present):")
    print(f"  source  : {result.source}  ← primary wins")
    print(f"  targets : {result.targets}")


if __name__ == "__main__":
    print("Zone Server Discovery Demo — spec §3.4 lookup order")

    demo_primary_lookup()
    demo_secondary_fallback()
    demo_anycast_fallback()
    demo_no_records()
    demo_precedence()

    print("\nDone.")
