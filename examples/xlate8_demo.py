#!/usr/bin/env python3
# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""XLATE8 north-south flow demo (Section 15)."""

from ipv8lab.address import IPv8Address
from ipv8lab.dns_a8 import A8Record
from ipv8lab.xlate8 import NorthSouthFlow

flow = NorthSouthFlow(zone_prefix="127.1.0.0", external_asn=64496)

flow.dns.add_record(A8Record(name="web.example.iv8", address=IPv8Address.parse("64497-10.0.1.100")))
flow.dns.add_record(A8Record(name="api.example.iv8", address=IPv8Address.parse("64498-10.0.2.50")))

internal = IPv8Address.parse("127.1.0.0.10.0.1.10")

scenarios = [
    ("web.example.iv8", 0, 0),
    ("api.example.iv8", 8080, 443),
    ("unknown.iv8", 0, 0),
]
for host, iport, eport in scenarios:
    kwargs = {}
    if iport:
        kwargs["internal_port"] = iport
    if eport:
        kwargs["external_port"] = eport
    eg, ig = flow.round_trip(hostname=host, internal_addr=internal, **kwargs)
    status = "OK" if eg and ig else "no DNS resolution"
    print(f"{host}: {status}")

print(f"\nXLATE entries: {len(flow.xlate_table.entries())}")
print(f"Events: {len(flow.events)} (all passed: {flow.all_events_passed})")
