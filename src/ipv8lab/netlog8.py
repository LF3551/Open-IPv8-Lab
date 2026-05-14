# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""NetLog8 telemetry client per draft-thain-ipv8-00.

NetLog8 is the unified telemetry format for all IPv8 network services.
Every IPv8 device (Tier 1/2/3) MUST implement a NetLog8 client.

The spec references NetLog8 in multiple contexts:
- Section 1.3: common telemetry format shared by all services
- Section 2.1: common telemetry format replacing fragmented syslog/SNMP
- Section 17.1: Tier 1 end devices MUST implement NetLog8 client
- Section 17.2: Tier 2 L2 devices MUST implement NetLog8 client
- Section 18.2: SEC-ALERT for internal zone prefix violations
- Section 18.3: SEC-ALERT for RINE prefix violations
- Section 18.4: E3 trap for interior link convention violations
- Section 18.7: SEC-ALERT for /16 minimum prefix violations
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from enum import IntEnum, auto
from typing import Any


class NetLog8Severity(IntEnum):
    """NetLog8 severity levels (syslog-compatible)."""

    EMERGENCY = 0   # System unusable
    ALERT = 1       # Immediate action required
    CRITICAL = 2    # Critical condition
    ERROR = 3       # Error condition
    WARNING = 4     # Warning condition
    NOTICE = 5      # Normal but significant
    INFO = 6        # Informational
    DEBUG = 7       # Debug-level


class NetLog8Facility(IntEnum):
    """NetLog8 facility codes."""

    KERNEL = 0
    ROUTING = auto()
    SECURITY = auto()
    DHCP8 = auto()
    DNS8 = auto()
    NTP8 = auto()
    OAUTH8 = auto()
    ACL8 = auto()
    WHOIS8 = auto()
    XLATE8 = auto()
    PVRST = auto()
    VRF = auto()
    ICMPV8 = auto()
    GENERAL = auto()


# Well-known event types from the spec
SEC_ALERT = "SEC-ALERT"
E3_TRAP = "E3"


@dataclass(frozen=True, slots=True)
class NetLog8Entry:
    """A single NetLog8 telemetry entry."""

    timestamp: float
    severity: NetLog8Severity
    facility: NetLog8Facility
    source: str            # device/service identifier
    event_type: str        # e.g. "SEC-ALERT", "E3", "INFO"
    message: str
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def priority(self) -> int:
        """RFC 5424-style priority = facility * 8 + severity."""
        return int(self.facility) * 8 + int(self.severity)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "severity": self.severity.name,
            "facility": self.facility.name,
            "source": self.source,
            "event_type": self.event_type,
            "message": self.message,
            "priority": self.priority,
            "metadata": dict(self.metadata),
        }


class NetLog8Client:
    """NetLog8 telemetry client.

    Collects telemetry entries locally with optional forwarding
    to a NetLog8 endpoint (Zone Server).  Supports severity filtering,
    buffer size limits, and structured queries.
    """

    def __init__(
        self,
        source: str,
        max_buffer: int = 10000,
        min_severity: NetLog8Severity = NetLog8Severity.DEBUG,
        endpoint: str = "",
    ) -> None:
        self._source = source
        self._max_buffer = max_buffer
        self._min_severity = min_severity
        self._endpoint = endpoint
        self._buffer: deque[NetLog8Entry] = deque(maxlen=max_buffer)
        self._counters: dict[NetLog8Severity, int] = {s: 0 for s in NetLog8Severity}
        self._clock: object = time.time

    def _now(self) -> float:
        return self._clock()  # type: ignore[operator]

    def log(
        self,
        severity: NetLog8Severity,
        facility: NetLog8Facility,
        message: str,
        event_type: str = "INFO",
        metadata: dict[str, Any] | None = None,
        timestamp: float | None = None,
    ) -> NetLog8Entry | None:
        """Record a telemetry entry.  Returns None if filtered."""
        if severity > self._min_severity:
            return None
        entry = NetLog8Entry(
            timestamp=timestamp if timestamp is not None else self._now(),
            severity=severity,
            facility=facility,
            source=self._source,
            event_type=event_type,
            message=message,
            metadata=metadata or {},
        )
        self._buffer.append(entry)
        self._counters[severity] += 1
        return entry

    # --- convenience methods for spec-referenced events ---

    def sec_alert(
        self,
        facility: NetLog8Facility,
        message: str,
        metadata: dict[str, Any] | None = None,
    ) -> NetLog8Entry | None:
        """SEC-ALERT per Sections 18.2, 18.3, 18.7."""
        return self.log(
            NetLog8Severity.ALERT, facility, message,
            event_type=SEC_ALERT, metadata=metadata,
        )

    def e3_trap(
        self,
        facility: NetLog8Facility,
        message: str,
        metadata: dict[str, Any] | None = None,
    ) -> NetLog8Entry | None:
        """E3 trap per Section 18.4."""
        return self.log(
            NetLog8Severity.ERROR, facility, message,
            event_type=E3_TRAP, metadata=metadata,
        )

    def info(
        self,
        facility: NetLog8Facility,
        message: str,
        metadata: dict[str, Any] | None = None,
    ) -> NetLog8Entry | None:
        return self.log(NetLog8Severity.INFO, facility, message, metadata=metadata)

    def warning(
        self,
        facility: NetLog8Facility,
        message: str,
        metadata: dict[str, Any] | None = None,
    ) -> NetLog8Entry | None:
        return self.log(NetLog8Severity.WARNING, facility, message,
                        event_type="WARNING", metadata=metadata)

    # --- query ---

    def query(
        self,
        severity: NetLog8Severity | None = None,
        facility: NetLog8Facility | None = None,
        event_type: str | None = None,
        limit: int = 100,
    ) -> list[NetLog8Entry]:
        """Query buffered entries with optional filters."""
        results: list[NetLog8Entry] = []
        for entry in reversed(self._buffer):
            if severity is not None and entry.severity != severity:
                continue
            if facility is not None and entry.facility != facility:
                continue
            if event_type is not None and entry.event_type != event_type:
                continue
            results.append(entry)
            if len(results) >= limit:
                break
        return results

    # --- properties ---

    @property
    def source(self) -> str:
        return self._source

    @property
    def endpoint(self) -> str:
        return self._endpoint

    @property
    def count(self) -> int:
        return len(self._buffer)

    @property
    def counters(self) -> dict[str, int]:
        return {s.name: c for s, c in self._counters.items() if c > 0}

    def clear(self) -> None:
        self._buffer.clear()
        self._counters = {s: 0 for s in NetLog8Severity}

    @property
    def entries(self) -> list[NetLog8Entry]:
        return list(self._buffer)
