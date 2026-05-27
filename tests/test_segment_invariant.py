# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for the per-segment one-Primary-RN invariant (spec §3.2)
and ARP8 Primary RN Discovery conflict detection."""

from __future__ import annotations

import pytest

from ipv8lab.address import IPv8Address
from ipv8lab.arp8_version import (
    PrimaryRNConflict,
    PrimaryRNConflictSeverity,
    PrimaryRNDiscovery,
)
from ipv8lab.compliance import Segment, SegmentViolation


# ---------------------------------------------------------------------------
# Segment — invariant enforcement
# ---------------------------------------------------------------------------

class TestSegment:
    def _addr(self, rn: int, host: str = "10.0.0.1") -> IPv8Address:
        return IPv8Address.parse(f"{rn}-{host}")

    def test_add_primary_address_matching_rn(self):
        seg = Segment(primary_rn=64496, name="test-seg")
        seg.add_primary_address(self._addr(64496))
        assert len(seg.primary_addresses) == 1

    def test_add_primary_address_wrong_rn_raises(self):
        seg = Segment(primary_rn=64496, name="test-seg")
        with pytest.raises(SegmentViolation, match="RN 64497"):
            seg.add_primary_address(self._addr(64497))

    def test_add_secondary_address_any_rn_allowed(self):
        seg = Segment(primary_rn=64496)
        seg.add_secondary_address(self._addr(64497, "10.0.0.2"))
        seg.add_secondary_address(self._addr(127, "10.0.0.3"))
        assert len(seg.secondary_addresses) == 2

    def test_validate_compliant(self):
        seg = Segment(primary_rn=64496)
        seg.add_primary_address(self._addr(64496, "10.0.0.1"))
        seg.add_primary_address(self._addr(64496, "10.0.0.2"))
        assert seg.validate() == []

    def test_validate_returns_violations_on_mismatch(self):
        # Force bad state by bypassing add_primary_address
        seg = Segment(primary_rn=64496)
        seg._primary_addrs.append(self._addr(64497))
        violations = seg.validate()
        assert len(violations) == 1
        assert "RN mismatch" in violations[0]

    def test_empty_segment_is_compliant(self):
        seg = Segment(primary_rn=64496)
        assert seg.validate() == []

    def test_multiple_primary_addrs_same_rn(self):
        seg = Segment(primary_rn=64496)
        for i in range(1, 6):
            seg.add_primary_address(self._addr(64496, f"10.0.0.{i}"))
        assert len(seg.primary_addresses) == 5
        assert seg.validate() == []

    def test_segment_name_optional(self):
        seg = Segment(primary_rn=0)
        assert seg.name == ""

    def test_segment_with_rn_zero(self):
        seg = Segment(primary_rn=0)
        seg.add_primary_address(self._addr(0, "8.8.8.8"))
        assert seg.validate() == []

    def test_violation_message_contains_canonical(self):
        seg = Segment(primary_rn=64496, name="corp-seg")
        with pytest.raises(SegmentViolation) as exc:
            seg.add_primary_address(self._addr(64497, "10.0.0.5"))
        assert "64497" in str(exc.value)
        assert "64496" in str(exc.value)


# ---------------------------------------------------------------------------
# PrimaryRNDiscovery — conflict detection
# ---------------------------------------------------------------------------

class TestPrimaryRNDiscovery:
    def test_matching_rn_returns_none(self):
        disc = PrimaryRNDiscovery(interface="eth0", expected_rn=64496)
        result = disc.observe("64496-10.0.0.2", announced_rn=64496)
        assert result is None
        assert not disc.forwarding_suspended
        assert disc.conflicts == []

    def test_conflicting_rn_returns_conflict(self):
        disc = PrimaryRNDiscovery(interface="eth0", expected_rn=64496)
        conflict = disc.observe("64497-10.0.0.2", announced_rn=64497)
        assert conflict is not None
        assert conflict.expected_rn == 64496
        assert conflict.observed_rn == 64497
        assert conflict.interface == "eth0"
        assert conflict.severity is PrimaryRNConflictSeverity.CONFLICT

    def test_conflict_suspends_forwarding(self):
        disc = PrimaryRNDiscovery(interface="eth0", expected_rn=64496)
        disc.observe("bad-neighbour-10.0.0.2", announced_rn=99999)
        assert disc.forwarding_suspended is True

    def test_multiple_conflicts_recorded(self):
        disc = PrimaryRNDiscovery(interface="eth0", expected_rn=64496)
        disc.observe("64497-10.0.0.2", 64497)
        disc.observe("64498-10.0.0.3", 64498)
        assert len(disc.conflicts) == 2

    def test_clear_conflict_resumes_forwarding(self):
        disc = PrimaryRNDiscovery(interface="eth0", expected_rn=64496)
        disc.observe("64497-10.0.0.2", 64497)
        assert disc.forwarding_suspended
        disc.clear_conflict()
        assert not disc.forwarding_suspended
        assert disc.conflicts == []

    def test_netlog8_event_format(self):
        disc = PrimaryRNDiscovery(interface="eth0", expected_rn=64496)
        conflict = disc.observe("64497-10.0.0.2", 64497)
        assert conflict is not None
        evt = conflict.netlog8_event
        assert "SEC-ALERT" in evt
        assert "primary-rn-conflict" in evt
        assert "eth0" in evt
        assert "64496" in evt
        assert "64497" in evt

    def test_no_conflict_no_suspension(self):
        disc = PrimaryRNDiscovery(interface="eth1", expected_rn=64496)
        for i in range(5):
            result = disc.observe(f"64496-10.0.0.{i}", 64496)
            assert result is None
        assert not disc.forwarding_suspended

    def test_conflict_detected_at_is_set(self):
        disc = PrimaryRNDiscovery(interface="eth0", expected_rn=64496)
        conflict = disc.observe("bad-10.0.0.1", 9999)
        assert conflict is not None
        assert conflict.detected_at > 0

    def test_rn_zero_segment(self):
        disc = PrimaryRNDiscovery(interface="eth0", expected_rn=0)
        assert disc.observe("0-8.8.8.1", 0) is None
        conflict = disc.observe("64496-10.0.0.1", 64496)
        assert conflict is not None
        assert conflict.expected_rn == 0
