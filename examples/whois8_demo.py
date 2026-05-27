#!/usr/bin/env python3
# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""WHOIS8 protocol demo: register ASN + lookup + route validation."""

from ipv8lab.whois8_proto import (
    WHOIS8Server,
    WHOIS8Client,
    WHOIS8ASNRecord,
    RouteRecord,
    RIR,
    ResponseCode,
)

server = WHOIS8Server()
client = WHOIS8Client(server)

records = [
    WHOIS8ASNRecord(asn=64496, holder="Acme Corp",   rir=RIR.ARIN,   country="US"),
    WHOIS8ASNRecord(asn=64497, holder="Globex Inc",  rir=RIR.RIPE,   country="DE"),
    WHOIS8ASNRecord(asn=64498, holder="Initech LLC", rir=RIR.APNIC,  country="JP"),
]
for r in records:
    server.register_asn(r)

server.register_route(RouteRecord(asn=64496, prefix_length=16))
server.register_route(RouteRecord(asn=64497, prefix_length=16))

print("=== Lookups ===")
for asn in (64496, 64497, 64498, 65000):
    resp = client.lookup(asn)
    if resp.code == ResponseCode.OK and resp.record:
        print(f"  AS{asn}: {resp.record.holder} ({resp.record.rir.value}, {resp.record.country})")
    else:
        print(f"  AS{asn}: {resp.code.value}")

print("\n=== Route validation ===")
valid = client.validate_route(64496, prefix_length=16)
print(f"  AS64496 /16: {valid.code.value}")
bad = client.validate_route(64498, prefix_length=16)
print(f"  AS64498 /16: {bad.code.value}")
