#!/usr/bin/env python3
# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Multi-zone simulation demo (Section 9)."""

from ipv8lab.multizone import MultiZoneSimulation, ZoneDefinition

sim = MultiZoneSimulation()
sim.add_zone(ZoneDefinition(name="americas", zone_octet=1))
sim.add_zone(ZoneDefinition(name="europe",   zone_octet=2))
sim.add_zone(ZoneDefinition(name="apac",     zone_octet=3))

sim.connect_zones("americas", "europe")
sim.connect_zones("europe", "apac")
sim.connect_zones("americas", "apac")

for zone, dev in [("americas", "dev-am"), ("europe", "dev-eu"), ("apac", "dev-ap")]:
    sim.provision_device(zone, dev)
    sim.authenticate_device(zone, dev)

print(f"Zones: {len(sim.zones)}  Links: {sim.link_count}")
for zone, dev in [("americas", "dev-am"), ("europe", "dev-eu"), ("apac", "dev-ap")]:
    lease = sim.get_zone(zone).dhcp_server.get_lease(dev)
    print(f"  {zone:<8} {dev:<8} {lease.address if lease else '—'}")
print(f"Events: {len(sim.events)}")
