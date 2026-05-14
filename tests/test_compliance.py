# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for device compliance tiers per Section 17.1-17.3."""

import pytest

from ipv8lab.compliance import (
    TIER1_OPTIONAL,
    TIER1_REQUIRED,
    TIER2_REQUIRED,
    TIER3_REQUIRED,
    Tier,
    check_compliance,
    highest_compliant_tier,
)


class TestTier1:
    def test_full_compliance(self):
        r = check_compliance(Tier.TIER1, TIER1_REQUIRED)
        assert r.compliant is True
        assert r.missing == frozenset()

    def test_missing_one(self):
        caps = TIER1_REQUIRED - {"icmpv8"}
        r = check_compliance(Tier.TIER1, caps)
        assert r.compliant is False
        assert "icmpv8" in r.missing

    def test_empty_capabilities(self):
        r = check_compliance(Tier.TIER1, set())
        assert r.compliant is False
        assert r.missing == TIER1_REQUIRED

    def test_optional_not_extra(self):
        caps = TIER1_REQUIRED | TIER1_OPTIONAL
        r = check_compliance(Tier.TIER1, caps)
        assert r.compliant is True
        assert r.extra == frozenset()

    def test_required_count(self):
        assert len(TIER1_REQUIRED) == 13


class TestTier2:
    def test_full_compliance(self):
        r = check_compliance(Tier.TIER2, TIER2_REQUIRED)
        assert r.compliant is True

    def test_missing_pvrst(self):
        caps = TIER2_REQUIRED - {"pvrst"}
        r = check_compliance(Tier.TIER2, caps)
        assert r.compliant is False
        assert "pvrst" in r.missing

    def test_required_count(self):
        assert len(TIER2_REQUIRED) == 13


class TestTier3:
    def test_full_compliance(self):
        r = check_compliance(Tier.TIER3, TIER3_REQUIRED)
        assert r.compliant is True

    def test_includes_tier1(self):
        assert TIER1_REQUIRED.issubset(TIER3_REQUIRED)

    def test_missing_ebgp8(self):
        caps = TIER3_REQUIRED - {"ebgp8"}
        r = check_compliance(Tier.TIER3, caps)
        assert r.compliant is False
        assert "ebgp8" in r.missing

    def test_has_xlate8(self):
        assert "xlate8" in TIER3_REQUIRED

    def test_has_whois8(self):
        assert "whois8_resolver" in TIER3_REQUIRED


class TestHighestTier:
    def test_tier3_device(self):
        caps = TIER3_REQUIRED | TIER2_REQUIRED
        assert highest_compliant_tier(caps) == Tier.TIER3

    def test_tier1_only(self):
        assert highest_compliant_tier(TIER1_REQUIRED) == Tier.TIER1

    def test_no_compliance(self):
        assert highest_compliant_tier(set()) is None

    def test_tier2_but_not_tier3(self):
        caps = TIER1_REQUIRED | TIER2_REQUIRED
        t = highest_compliant_tier(caps)
        # Tier 2 compliant (has all T2 reqs), Tier 1 compliant
        # But not Tier 3 (missing L3-specific reqs)
        assert t is not None
        assert t.value <= 2


class TestComplianceResult:
    def test_frozen(self):
        r = check_compliance(Tier.TIER1, TIER1_REQUIRED)
        with pytest.raises(AttributeError):
            r.compliant = False  # type: ignore[misc]

    def test_present_field(self):
        r = check_compliance(Tier.TIER1, TIER1_REQUIRED)
        assert r.present == TIER1_REQUIRED
