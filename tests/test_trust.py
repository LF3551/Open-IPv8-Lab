# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for trust-state update discipline (Step 12)."""

from __future__ import annotations

import pytest

from ipv8lab.trust import (
    TrustDiff,
    TrustDomain,
    TrustEntry,
    TrustRegistry,
    TrustStore,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _e(key: str, value: bytes = b"v") -> TrustEntry:
    return TrustEntry(key=key, value=value)


def _store(domain: TrustDomain = TrustDomain.RINE_MEMBERS, clock_val: float = 0.0) -> TrustStore:
    return TrustStore(domain, clock=lambda: clock_val)


# ---------------------------------------------------------------------------
# TrustEntry
# ---------------------------------------------------------------------------

class TestTrustEntry:
    def test_digest_deterministic(self):
        e = _e("k1", b"abc")
        assert e.digest() == e.digest()

    def test_different_keys_different_digest(self):
        assert _e("k1").digest() != _e("k2").digest()

    def test_different_values_different_digest(self):
        e1 = TrustEntry("k", b"a")
        e2 = TrustEntry("k", b"b")
        assert e1.digest() != e2.digest()


# ---------------------------------------------------------------------------
# TrustDiff
# ---------------------------------------------------------------------------

class TestTrustDiff:
    def test_has_changes_false_when_empty(self):
        d = TrustDiff(added=(), removed=(), changed=(), unchanged=3)
        assert not d.has_changes

    def test_has_changes_true_when_added(self):
        d = TrustDiff(added=(_e("k"),), removed=(), changed=(), unchanged=0)
        assert d.has_changes

    def test_summary_format(self):
        d = TrustDiff(added=(_e("a"),), removed=(), changed=(_e("b"),), unchanged=5)
        assert "+1" in d.summary
        assert "~1" in d.summary
        assert "=5" in d.summary


# ---------------------------------------------------------------------------
# TrustStore — verify (read-only)
# ---------------------------------------------------------------------------

class TestTrustStoreVerify:
    def test_verify_detects_added(self):
        s = _store()
        s.load([_e("k1")])
        diff = s.verify([_e("k1"), _e("k2")])
        assert len(diff.added) == 1
        assert diff.added[0].key == "k2"

    def test_verify_detects_removed(self):
        s = _store()
        s.load([_e("k1"), _e("k2")])
        diff = s.verify([_e("k1")])
        assert len(diff.removed) == 1
        assert diff.removed[0].key == "k2"

    def test_verify_detects_changed(self):
        s = _store()
        s.load([TrustEntry("k1", b"old")])
        diff = s.verify([TrustEntry("k1", b"new")])
        assert len(diff.changed) == 1

    def test_verify_does_not_modify(self):
        s = _store()
        s.load([_e("k1")])
        s.verify([_e("k2")])
        assert s.get("k1") is not None   # original still there
        assert s.get("k2") is None       # not installed

    def test_verify_unchanged_count(self):
        s = _store()
        s.load([_e("k1"), _e("k2")])
        diff = s.verify([_e("k1"), _e("k2")])
        assert diff.unchanged == 2
        assert not diff.has_changes


# ---------------------------------------------------------------------------
# TrustStore — update (installs + snapshots)
# ---------------------------------------------------------------------------

class TestTrustStoreUpdate:
    def test_update_installs_entries(self):
        s = _store()
        s.load([_e("k1")])
        s.update([_e("k2")])
        assert s.get("k2") is not None
        assert s.get("k1") is None  # replaced

    def test_update_bumps_version(self):
        s = _store()
        assert s.version == 0
        s.update([_e("k1")])
        assert s.version == 1

    def test_update_creates_snapshot(self):
        s = _store()
        s.load([_e("k1")])
        s.update([_e("k2")])
        assert s.snapshot_count == 1

    def test_update_returns_diff(self):
        s = _store()
        s.load([_e("k1")])
        diff = s.update([_e("k2")])
        assert isinstance(diff, TrustDiff)
        assert len(diff.added) == 1
        assert len(diff.removed) == 1

    def test_max_snapshots_respected(self):
        s = TrustStore(TrustDomain.SUN_TZU, max_snapshots=3, clock=lambda: 0.0)
        for i in range(6):
            s.update([_e(f"k{i}")])
        assert s.snapshot_count <= 3


# ---------------------------------------------------------------------------
# TrustStore — rollback
# ---------------------------------------------------------------------------

class TestTrustStoreRollback:
    def test_rollback_restores_previous(self):
        s = _store()
        s.load([_e("k1")])
        s.update([_e("k2")])
        assert s.rollback()
        assert s.get("k1") is not None

    def test_rollback_decrements_snapshot_count(self):
        s = _store()
        s.load([_e("k1")])
        s.update([_e("k2")])
        s.rollback()
        assert s.snapshot_count == 0

    def test_rollback_fails_when_no_snapshots(self):
        s = _store()
        assert not s.rollback()

    def test_rollback_two_steps(self):
        s = _store()
        s.load([_e("orig")])
        s.update([_e("v1")])
        s.update([_e("v2")])
        assert s.rollback(steps=2)
        assert s.get("orig") is not None

    def test_rollback_too_many_steps_fails(self):
        s = _store()
        s.load([_e("k1")])
        s.update([_e("k2")])
        assert not s.rollback(steps=5)


# ---------------------------------------------------------------------------
# TrustStore — stale warning
# ---------------------------------------------------------------------------

class TestTrustStoreStale:
    def test_fresh_is_not_stale(self):
        now = 1_000_000.0
        s = TrustStore(TrustDomain.RIR_ANCHORS, stale_days=7, clock=lambda: now)
        s.load([_e("k1")], timestamp=now)
        assert not s.is_stale()

    def test_stale_after_threshold(self):
        base = 0.0
        s = TrustStore(
            TrustDomain.RIR_ANCHORS,
            stale_days=7,
            clock=lambda: base + 8 * 86400,
        )
        s.load([_e("k1")], timestamp=base)
        assert s.is_stale()

    def test_stale_warning_returns_string(self):
        base = 0.0
        s = TrustStore(
            TrustDomain.RIR_ANCHORS,
            stale_days=7,
            clock=lambda: base + 8 * 86400,
        )
        s.load([_e("k1")], timestamp=base)
        w = s.stale_warning()
        assert w is not None
        assert "WARNING" in w
        assert "rir_anchors" in w

    def test_fresh_warning_returns_none(self):
        now = 1_000_000.0
        s = TrustStore(TrustDomain.WHOIS8_CERT, stale_days=7, clock=lambda: now)
        s.load([_e("k1")], timestamp=now)
        assert s.stale_warning() is None

    def test_never_loaded_is_stale(self):
        s = TrustStore(TrustDomain.ANYCAST_ROA, clock=lambda: 0.0)
        assert s.is_stale()


# ---------------------------------------------------------------------------
# TrustRegistry
# ---------------------------------------------------------------------------

class TestTrustRegistry:
    def test_has_all_domains(self):
        reg = TrustRegistry(clock=lambda: 0.0)
        for d in TrustDomain:
            assert reg.store(d) is not None

    def test_verify_all(self):
        reg = TrustRegistry(clock=lambda: 0.0)
        upstreams = {
            TrustDomain.RINE_MEMBERS: [_e("rn1")],
            TrustDomain.SUN_TZU: [_e("sz1")],
        }
        diffs = reg.verify_all(upstreams)
        assert TrustDomain.RINE_MEMBERS in diffs
        assert TrustDomain.SUN_TZU in diffs

    def test_update_all(self):
        reg = TrustRegistry(clock=lambda: 0.0)
        upstreams = {d: [_e(f"{d.value}-k")] for d in TrustDomain}
        diffs = reg.update_all(upstreams)
        assert len(diffs) == len(TrustDomain)

    def test_stale_warnings_all_stale(self):
        # All never loaded → all stale
        reg = TrustRegistry(stale_days=7, clock=lambda: 0.0)
        warnings = reg.stale_warnings()
        assert len(warnings) == len(TrustDomain)

    def test_any_stale(self):
        reg = TrustRegistry(clock=lambda: 0.0)
        assert reg.any_stale()

    def test_no_stale_when_all_fresh(self):
        now = 1_000_000.0
        reg = TrustRegistry(stale_days=7, clock=lambda: now)
        for d in TrustDomain:
            reg.store(d).load([_e("k")], timestamp=now)
        assert not reg.any_stale()
        assert reg.stale_warnings() == []
