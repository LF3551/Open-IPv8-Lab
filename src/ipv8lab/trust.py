# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Trust-state update discipline.

Every trust store (AnycastROA filter, WHOIS8 cert trust, RIR anchors,
RINE region membership, Sun Tzu baseline) exposes exactly **two**
operator commands:

* :meth:`TrustStore.verify` — diff upstream vs local; no modification.
* :meth:`TrustStore.update` — install upstream, snapshot old state.

Additionally:

* Console warning when state hasn't been refreshed for ≥ ``stale_days``
  (default 7, configurable).
* Previous N versions retained for :meth:`TrustStore.rollback`.
"""

from __future__ import annotations

import hashlib
import time as _time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Trust store names (the five trust domains)
# ---------------------------------------------------------------------------

class TrustDomain(str, Enum):
    """Named trust domains covered by the update discipline."""

    ANYCAST_ROA  = "anycast_roa"     # AnycastROA filter
    WHOIS8_CERT  = "whois8_cert"     # WHOIS8 certificate trust
    RIR_ANCHORS  = "rir_anchors"     # RIR root anchors
    RINE_MEMBERS = "rine_members"    # RINE region membership
    SUN_TZU      = "sun_tzu"         # Sun Tzu baseline


# ---------------------------------------------------------------------------
# Trust entry
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class TrustEntry:
    """One record in a trust store.

    *key* uniquely identifies the record (e.g. ASN, fingerprint, RN).
    *value* is the opaque payload (cert bytes, ROA blob, etc.).
    """

    key: str
    value: bytes
    meta: dict[str, Any] = field(default_factory=dict)

    def digest(self) -> str:
        """SHA-256 hex digest of (key + value)."""
        h = hashlib.sha256(self.key.encode() + self.value)
        return h.hexdigest()


# ---------------------------------------------------------------------------
# Diff result
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class TrustDiff:
    """Result of a :meth:`TrustStore.verify` or :meth:`TrustStore.update` call.

    No entries are modified when this object is produced by *verify*.
    """

    added: tuple[TrustEntry, ...]     # present in upstream, absent locally
    removed: tuple[TrustEntry, ...]   # present locally, absent in upstream
    changed: tuple[TrustEntry, ...]   # key matches but value differs
    unchanged: int                    # count of identical entries

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed or self.changed)

    @property
    def summary(self) -> str:
        return (
            f"+{len(self.added)} -{len(self.removed)} ~{len(self.changed)} "
            f"={self.unchanged}"
        )


# ---------------------------------------------------------------------------
# Trust store snapshot
# ---------------------------------------------------------------------------

@dataclass
class TrustSnapshot:
    """Immutable snapshot of a trust store at a point in time."""

    entries: dict[str, TrustEntry]   # key → entry
    timestamp: float
    version: int


# ---------------------------------------------------------------------------
# Trust store
# ---------------------------------------------------------------------------

_STALE_DAYS_DEFAULT = 7


class TrustStore:
    """Versioned trust store with verify/update/rollback/stale-warning.

    Parameters
    ----------
    domain:
        Identifies which trust domain this store belongs to.
    max_snapshots:
        How many previous versions to keep for rollback (default 5).
    stale_days:
        Warn when state hasn't been refreshed for this many days.
    clock:
        Callable returning current time as float (default ``time.time``).
    """

    def __init__(
        self,
        domain: TrustDomain,
        *,
        max_snapshots: int = 5,
        stale_days: int = _STALE_DAYS_DEFAULT,
        clock: Any = None,
    ) -> None:
        self._domain = domain
        self._max_snapshots = max(1, max_snapshots)
        self._stale_days = stale_days
        self._clock: Any = clock if clock is not None else _time.time

        self._entries: dict[str, TrustEntry] = {}
        self._snapshots: list[TrustSnapshot] = []
        self._version: int = 0
        self._last_updated: float | None = None

    # ----------------------------------------------------------------
    # Properties
    # ----------------------------------------------------------------

    @property
    def domain(self) -> TrustDomain:
        return self._domain

    @property
    def version(self) -> int:
        return self._version

    @property
    def entry_count(self) -> int:
        return len(self._entries)

    @property
    def last_updated(self) -> float | None:
        return self._last_updated

    @property
    def snapshot_count(self) -> int:
        return len(self._snapshots)

    # ----------------------------------------------------------------
    # Load initial state (does NOT count as an update)
    # ----------------------------------------------------------------

    def load(self, entries: list[TrustEntry], timestamp: float | None = None) -> None:
        """Populate the store without creating a snapshot or bumping version."""
        self._entries = {e.key: e for e in entries}
        self._last_updated = timestamp if timestamp is not None else self._clock()

    # ----------------------------------------------------------------
    # Verify — read-only diff
    # ----------------------------------------------------------------

    def verify(self, upstream: list[TrustEntry]) -> TrustDiff:
        """Diff upstream entries against local state.  No modification.

        This is a **read-only** operation; call :meth:`update` to install.
        """
        return self._compute_diff(upstream)

    # ----------------------------------------------------------------
    # Update — install upstream, snapshot old state
    # ----------------------------------------------------------------

    def update(self, upstream: list[TrustEntry]) -> TrustDiff:
        """Install *upstream* entries after computing the diff.

        Saves a snapshot of the old state first so :meth:`rollback`
        can restore it.  Returns the diff for operator review.
        """
        diff = self._compute_diff(upstream)
        # Save snapshot before modifying
        self._push_snapshot()
        # Apply upstream
        self._entries = {e.key: e for e in upstream}
        self._version += 1
        self._last_updated = self._clock()
        return diff

    # ----------------------------------------------------------------
    # Rollback
    # ----------------------------------------------------------------

    def rollback(self, steps: int = 1) -> bool:
        """Restore the state *steps* versions back.

        Returns False if there aren't enough snapshots.
        """
        if steps < 1 or steps > len(self._snapshots):
            return False
        snap = self._snapshots[-steps]
        self._entries = dict(snap.entries)
        self._version = snap.version
        # Remove snapshots newer than the restored point
        self._snapshots = self._snapshots[:-steps]
        return True

    # ----------------------------------------------------------------
    # Stale warning
    # ----------------------------------------------------------------

    def is_stale(self) -> bool:
        """True if state hasn't been refreshed for ≥ *stale_days* days."""
        if self._last_updated is None:
            return True
        age_days = (self._clock() - self._last_updated) / 86400
        return age_days >= self._stale_days

    def stale_warning(self) -> str | None:
        """Return a warning string if stale, else None."""
        if not self.is_stale():
            return None
        age_days = (
            (self._clock() - self._last_updated) / 86400
            if self._last_updated is not None
            else float("inf")
        )
        return (
            f"WARNING: {self._domain.value} trust state is stale "
            f"({age_days:.1f}d ≥ {self._stale_days}d refresh threshold)"
        )

    # ----------------------------------------------------------------
    # Introspection
    # ----------------------------------------------------------------

    def entries(self) -> list[TrustEntry]:
        return list(self._entries.values())

    def get(self, key: str) -> TrustEntry | None:
        return self._entries.get(key)

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self._domain.value,
            "version": self._version,
            "entries": self.entry_count,
            "snapshots": self.snapshot_count,
            "stale": self.is_stale(),
        }

    # ----------------------------------------------------------------
    # Internal helpers
    # ----------------------------------------------------------------

    def _compute_diff(self, upstream: list[TrustEntry]) -> TrustDiff:
        upstream_map = {e.key: e for e in upstream}
        local_map = self._entries

        added = tuple(e for k, e in upstream_map.items() if k not in local_map)
        removed = tuple(e for k, e in local_map.items() if k not in upstream_map)
        changed = tuple(
            upstream_map[k]
            for k in upstream_map
            if k in local_map and upstream_map[k].value != local_map[k].value
        )
        unchanged = sum(
            1 for k in upstream_map
            if k in local_map and upstream_map[k].value == local_map[k].value
        )
        return TrustDiff(
            added=added,
            removed=removed,
            changed=changed,
            unchanged=unchanged,
        )

    def _push_snapshot(self) -> None:
        snap = TrustSnapshot(
            entries=dict(self._entries),
            timestamp=self._clock(),
            version=self._version,
        )
        self._snapshots.append(snap)
        if len(self._snapshots) > self._max_snapshots:
            self._snapshots = self._snapshots[-self._max_snapshots:]


# ---------------------------------------------------------------------------
# Trust store registry
# ---------------------------------------------------------------------------

class TrustRegistry:
    """Holds one :class:`TrustStore` per :class:`TrustDomain`.

    Provides a unified interface for batch verify/update/stale-check
    across all trust domains.
    """

    def __init__(self, **kwargs: Any) -> None:
        """*kwargs* are passed to every :class:`TrustStore` constructor."""
        self._stores: dict[TrustDomain, TrustStore] = {
            d: TrustStore(d, **kwargs) for d in TrustDomain
        }

    def store(self, domain: TrustDomain) -> TrustStore:
        return self._stores[domain]

    def verify_all(
        self, upstreams: dict[TrustDomain, list[TrustEntry]],
    ) -> dict[TrustDomain, TrustDiff]:
        """Verify all domains; returns diffs keyed by domain."""
        return {d: self._stores[d].verify(entries) for d, entries in upstreams.items()}

    def update_all(
        self, upstreams: dict[TrustDomain, list[TrustEntry]],
    ) -> dict[TrustDomain, TrustDiff]:
        """Update all domains; returns diffs keyed by domain."""
        return {d: self._stores[d].update(entries) for d, entries in upstreams.items()}

    def stale_warnings(self) -> list[str]:
        """Return warning strings for all stale domains."""
        return [
            w for s in self._stores.values()
            if (w := s.stale_warning()) is not None
        ]

    def any_stale(self) -> bool:
        return any(s.is_stale() for s in self._stores.values())
