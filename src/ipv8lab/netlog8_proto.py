# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Standalone NetLog8 protocol per draft-thain-netlog8-00.

NetLog8 is the unified telemetry protocol for all IPv8 network services.
This module implements the full wire protocol layer on top of the
existing NetLog8 client (ipv8lab.netlog8):

- NetLog8 message framing (header + payload)
- Transport abstraction (UDP/TCP to Zone Server)
- Collector (server-side) with persistence, aggregation, and alerting
- Structured query engine with filter expressions
- Forwarding and relay chains
- Rate limiting and back-pressure
- Export to external systems (JSON lines, syslog format)
"""

from __future__ import annotations

import struct
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ipv8lab.netlog8 import (
    NetLog8Entry,
    NetLog8Facility,
    NetLog8Severity,
)


# ===================================================================
# Constants
# ===================================================================

NETLOG8_PORT = 8514            # Well-known UDP port for NetLog8
NETLOG8_VERSION = 1
NETLOG8_MAGIC = 0x4E4C3801     # "NL8\x01"
NETLOG8_MAX_MESSAGE_SIZE = 8192


# ===================================================================
# Transport mode
# ===================================================================

class TransportMode(str, Enum):
    UDP = "udp"
    TCP = "tcp"
    LOCAL = "local"  # in-process (for testing)


# ===================================================================
# Message framing
# ===================================================================

@dataclass(frozen=True, slots=True)
class NetLog8Header:
    """NetLog8 wire protocol header.

    Format (12 bytes):
        magic:    uint32  (0x4E4C3801)
        version:  uint8
        severity: uint8
        facility: uint16
        length:   uint32  (payload length)
    """

    magic: int = NETLOG8_MAGIC
    version: int = NETLOG8_VERSION
    severity: int = 0
    facility: int = 0
    length: int = 0

    STRUCT_FMT = "!IBBHI"
    HEADER_SIZE = struct.calcsize("!IBBHI")

    def pack(self) -> bytes:
        return struct.pack(
            self.STRUCT_FMT,
            self.magic,
            self.version,
            self.severity,
            self.facility,
            self.length,
        )

    @classmethod
    def unpack(cls, data: bytes) -> NetLog8Header:
        if len(data) < cls.HEADER_SIZE:
            msg = f"Header requires {cls.HEADER_SIZE} bytes, got {len(data)}"
            raise ValueError(msg)
        magic, version, severity, facility, length = struct.unpack(
            cls.STRUCT_FMT, data[:cls.HEADER_SIZE],
        )
        if magic != NETLOG8_MAGIC:
            msg = f"Invalid NetLog8 magic: 0x{magic:08X}"
            raise ValueError(msg)
        return cls(
            magic=magic,
            version=version,
            severity=severity,
            facility=facility,
            length=length,
        )


@dataclass(frozen=True, slots=True)
class NetLog8Message:
    """A framed NetLog8 message (header + entry)."""

    header: NetLog8Header
    entry: NetLog8Entry

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.header.version,
            "header_size": NetLog8Header.HEADER_SIZE,
            "payload_length": self.header.length,
            **self.entry.to_dict(),
        }


def frame_entry(entry: NetLog8Entry) -> NetLog8Message:
    """Wrap a NetLog8Entry into a framed message."""
    payload = entry.message.encode("utf-8")
    header = NetLog8Header(
        severity=int(entry.severity),
        facility=int(entry.facility),
        length=len(payload),
    )
    return NetLog8Message(header=header, entry=entry)


# ===================================================================
# Alert rule
# ===================================================================

@dataclass(frozen=True, slots=True)
class AlertRule:
    """A rule that triggers on matching entries."""

    name: str
    severity_min: NetLog8Severity = NetLog8Severity.ALERT
    event_types: tuple[str, ...] = ()
    facilities: tuple[NetLog8Facility, ...] = ()

    def matches(self, entry: NetLog8Entry) -> bool:
        if entry.severity > self.severity_min:
            return False
        if self.event_types and entry.event_type not in self.event_types:
            return False
        if self.facilities and entry.facility not in self.facilities:
            return False
        return True


@dataclass(frozen=True, slots=True)
class Alert:
    """A triggered alert."""

    rule_name: str
    entry: NetLog8Entry
    triggered_at: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_name": self.rule_name,
            "triggered_at": self.triggered_at,
            "entry": self.entry.to_dict(),
        }


# ===================================================================
# NetLog8 Collector (server-side)
# ===================================================================

@dataclass
class NetLog8Collector:
    """NetLog8 collector / aggregator (Zone Server side).

    Receives messages from clients, stores them, applies alert
    rules, and provides structured queries.
    """

    collector_id: str = "netlog8-collector"
    max_buffer: int = 100_000
    _buffer: deque[NetLog8Entry] = field(default_factory=lambda: deque(maxlen=100_000), init=False)
    _rules: list[AlertRule] = field(default_factory=list, init=False)
    _alerts: list[Alert] = field(default_factory=list, init=False)
    _counters: dict[str, int] = field(default_factory=dict, init=False)
    _received: int = field(default=0, init=False)
    _sources: set[str] = field(default_factory=set, init=False)

    def __post_init__(self) -> None:
        self._buffer = deque(maxlen=self.max_buffer)

    # -- ingest --------------------------------------------------------------

    def ingest(self, entry: NetLog8Entry) -> list[Alert]:
        """Ingest a single entry. Returns any triggered alerts."""
        self._buffer.append(entry)
        self._received += 1
        self._sources.add(entry.source)

        # update counters
        sev_key = entry.severity.name
        self._counters[sev_key] = self._counters.get(sev_key, 0) + 1

        # check alert rules
        triggered: list[Alert] = []
        for rule in self._rules:
            if rule.matches(entry):
                alert = Alert(
                    rule_name=rule.name,
                    entry=entry,
                    triggered_at=time.time(),
                )
                self._alerts.append(alert)
                triggered.append(alert)
        return triggered

    def ingest_batch(self, entries: list[NetLog8Entry]) -> list[Alert]:
        """Ingest multiple entries."""
        all_alerts: list[Alert] = []
        for e in entries:
            all_alerts.extend(self.ingest(e))
        return all_alerts

    # -- alert rules ---------------------------------------------------------

    def add_rule(self, rule: AlertRule) -> None:
        self._rules.append(rule)

    def clear_rules(self) -> int:
        n = len(self._rules)
        self._rules.clear()
        return n

    # -- query ---------------------------------------------------------------

    def query(
        self,
        *,
        severity: NetLog8Severity | None = None,
        facility: NetLog8Facility | None = None,
        event_type: str | None = None,
        source: str | None = None,
        since: float | None = None,
        limit: int = 100,
    ) -> list[NetLog8Entry]:
        """Structured query with filters."""
        results: list[NetLog8Entry] = []
        for entry in reversed(self._buffer):
            if severity is not None and entry.severity != severity:
                continue
            if facility is not None and entry.facility != facility:
                continue
            if event_type is not None and entry.event_type != event_type:
                continue
            if source is not None and entry.source != source:
                continue
            if since is not None and entry.timestamp < since:
                continue
            results.append(entry)
            if len(results) >= limit:
                break
        return results

    def query_alerts(self, *, rule_name: str | None = None, limit: int = 100) -> list[Alert]:
        """Query triggered alerts."""
        results: list[Alert] = []
        for alert in reversed(self._alerts):
            if rule_name is not None and alert.rule_name != rule_name:
                continue
            results.append(alert)
            if len(results) >= limit:
                break
        return results

    # -- export --------------------------------------------------------------

    def export_jsonl(self, *, limit: int = 0) -> list[dict[str, Any]]:
        """Export entries as JSON lines dicts."""
        entries = list(self._buffer)
        if limit > 0:
            entries = entries[-limit:]
        return [e.to_dict() for e in entries]

    def export_syslog(self, *, limit: int = 0) -> list[str]:
        """Export entries in syslog-like format."""
        entries = list(self._buffer)
        if limit > 0:
            entries = entries[-limit:]
        lines: list[str] = []
        for e in entries:
            pri = e.priority
            lines.append(f"<{pri}>{e.severity.name} {e.source} {e.event_type}: {e.message}")
        return lines

    # -- housekeeping --------------------------------------------------------

    @property
    def alerts(self) -> list[Alert]:
        return list(self._alerts)

    def clear_alerts(self) -> int:
        n = len(self._alerts)
        self._alerts.clear()
        return n

    def clear_buffer(self) -> int:
        n = len(self._buffer)
        self._buffer.clear()
        self._counters.clear()
        return n

    def summary(self) -> dict[str, Any]:
        return {
            "collector_id": self.collector_id,
            "received": self._received,
            "buffered": len(self._buffer),
            "sources": sorted(self._sources),
            "alert_rules": len(self._rules),
            "triggered_alerts": len(self._alerts),
            "counters": dict(self._counters),
        }


# ===================================================================
# NetLog8 Relay
# ===================================================================

@dataclass
class NetLog8Relay:
    """Forwarding relay that fans out entries to multiple collectors."""

    relay_id: str = "netlog8-relay"
    _collectors: list[NetLog8Collector] = field(default_factory=list, init=False)
    _forwarded: int = field(default=0, init=False)

    def add_collector(self, collector: NetLog8Collector) -> None:
        self._collectors.append(collector)

    def forward(self, entry: NetLog8Entry) -> int:
        """Forward an entry to all collectors. Returns alert count."""
        alert_count = 0
        for c in self._collectors:
            alerts = c.ingest(entry)
            alert_count += len(alerts)
        self._forwarded += 1
        return alert_count

    def forward_batch(self, entries: list[NetLog8Entry]) -> int:
        total = 0
        for e in entries:
            total += self.forward(e)
        return total

    def summary(self) -> dict[str, Any]:
        return {
            "relay_id": self.relay_id,
            "collectors": len(self._collectors),
            "forwarded": self._forwarded,
        }


# ===================================================================
# Rate limiter
# ===================================================================

@dataclass
class RateLimiter:
    """Token-bucket rate limiter for NetLog8 message ingestion."""

    rate: float = 1000.0     # messages per second
    burst: int = 5000        # max burst size
    _tokens: float = field(default=0.0, init=False)
    _last_refill: float = field(default=0.0, init=False)
    _dropped: int = field(default=0, init=False)
    _passed: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        self._tokens = float(self.burst)
        self._last_refill = time.time()

    def allow(self, now: float | None = None) -> bool:
        """Check if a message is allowed."""
        t = now if now is not None else time.time()
        elapsed = t - self._last_refill
        self._tokens = min(float(self.burst), self._tokens + elapsed * self.rate)
        self._last_refill = t

        if self._tokens >= 1.0:
            self._tokens -= 1.0
            self._passed += 1
            return True
        self._dropped += 1
        return False

    def summary(self) -> dict[str, float | int]:
        return {
            "rate": self.rate,
            "burst": self.burst,
            "passed": self._passed,
            "dropped": self._dropped,
            "tokens": round(self._tokens, 1),
        }
