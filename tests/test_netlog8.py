# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for NetLog8 telemetry client."""

import pytest

from ipv8lab.netlog8 import (
    E3_TRAP,
    SEC_ALERT,
    NetLog8Client,
    NetLog8Entry,
    NetLog8Facility,
    NetLog8Severity,
)


class _FakeClock:
    def __init__(self, now: float = 0.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


@pytest.fixture()
def client() -> NetLog8Client:
    c = NetLog8Client(source="router-1", endpoint="netlog.zone")
    c._clock = _FakeClock(1000.0)
    return c


# ---------------------------------------------------------------------------
# Severity / Facility enums
# ---------------------------------------------------------------------------

class TestEnums:
    def test_severity_order(self):
        assert NetLog8Severity.EMERGENCY < NetLog8Severity.DEBUG

    def test_severity_count(self):
        assert len(NetLog8Severity) == 8

    def test_facility_values(self):
        names = {f.name for f in NetLog8Facility}
        assert "ROUTING" in names
        assert "SECURITY" in names
        assert "DHCP8" in names
        assert "ACL8" in names
        assert "WHOIS8" in names


# ---------------------------------------------------------------------------
# NetLog8Entry
# ---------------------------------------------------------------------------

class TestNetLog8Entry:
    def test_priority(self):
        entry = NetLog8Entry(
            timestamp=0.0,
            severity=NetLog8Severity.ALERT,
            facility=NetLog8Facility.SECURITY,
            source="r1",
            event_type=SEC_ALERT,
            message="test",
        )
        # priority = facility * 8 + severity = 2 * 8 + 1 = 17
        assert entry.priority == int(NetLog8Facility.SECURITY) * 8 + 1

    def test_to_dict(self):
        entry = NetLog8Entry(
            timestamp=123.0,
            severity=NetLog8Severity.INFO,
            facility=NetLog8Facility.GENERAL,
            source="d1",
            event_type="INFO",
            message="hello",
            metadata={"key": "val"},
        )
        d = entry.to_dict()
        assert d["severity"] == "INFO"
        assert d["facility"] == "GENERAL"
        assert d["message"] == "hello"
        assert d["metadata"] == {"key": "val"}
        assert "priority" in d
        assert d["timestamp"] == 123.0


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

class TestLogging:
    def test_basic_log(self, client: NetLog8Client):
        entry = client.log(
            NetLog8Severity.INFO,
            NetLog8Facility.ROUTING,
            "route added",
        )
        assert entry is not None
        assert entry.source == "router-1"
        assert entry.severity == NetLog8Severity.INFO
        assert entry.timestamp == 1000.0
        assert client.count == 1

    def test_severity_filtering(self):
        c = NetLog8Client(source="r1", min_severity=NetLog8Severity.WARNING)
        c._clock = _FakeClock()
        assert c.log(NetLog8Severity.INFO, NetLog8Facility.GENERAL, "skip") is None
        assert c.log(NetLog8Severity.DEBUG, NetLog8Facility.GENERAL, "skip") is None
        assert c.log(NetLog8Severity.WARNING, NetLog8Facility.GENERAL, "ok") is not None
        assert c.log(NetLog8Severity.ERROR, NetLog8Facility.GENERAL, "ok") is not None
        assert c.count == 2

    def test_buffer_limit(self):
        c = NetLog8Client(source="r1", max_buffer=3)
        c._clock = _FakeClock()
        for i in range(5):
            c.log(NetLog8Severity.INFO, NetLog8Facility.GENERAL, f"msg-{i}")
        assert c.count == 3
        msgs = [e.message for e in c.entries]
        assert msgs == ["msg-2", "msg-3", "msg-4"]

    def test_custom_timestamp(self, client: NetLog8Client):
        entry = client.log(
            NetLog8Severity.INFO, NetLog8Facility.GENERAL,
            "custom", timestamp=999.0,
        )
        assert entry is not None
        assert entry.timestamp == 999.0

    def test_metadata(self, client: NetLog8Client):
        entry = client.log(
            NetLog8Severity.INFO, NetLog8Facility.ROUTING,
            "test", metadata={"asn": 64496},
        )
        assert entry is not None
        assert entry.metadata == {"asn": 64496}


# ---------------------------------------------------------------------------
# Convenience methods
# ---------------------------------------------------------------------------

class TestConvenience:
    def test_sec_alert(self, client: NetLog8Client):
        entry = client.sec_alert(
            NetLog8Facility.SECURITY,
            "internal zone prefix on WAN",
            metadata={"prefix": "127.1.0.0"},
        )
        assert entry is not None
        assert entry.event_type == SEC_ALERT
        assert entry.severity == NetLog8Severity.ALERT

    def test_e3_trap(self, client: NetLog8Client):
        entry = client.e3_trap(
            NetLog8Facility.ROUTING,
            "222.x.x.x in BGP advertisement",
        )
        assert entry is not None
        assert entry.event_type == E3_TRAP
        assert entry.severity == NetLog8Severity.ERROR

    def test_info(self, client: NetLog8Client):
        entry = client.info(NetLog8Facility.DHCP8, "lease granted")
        assert entry is not None
        assert entry.severity == NetLog8Severity.INFO

    def test_warning(self, client: NetLog8Client):
        entry = client.warning(NetLog8Facility.OAUTH8, "token near expiry")
        assert entry is not None
        assert entry.severity == NetLog8Severity.WARNING
        assert entry.event_type == "WARNING"


# ---------------------------------------------------------------------------
# Query
# ---------------------------------------------------------------------------

class TestQuery:
    def test_query_by_severity(self, client: NetLog8Client):
        client.info(NetLog8Facility.GENERAL, "msg1")
        client.sec_alert(NetLog8Facility.SECURITY, "alert1")
        client.info(NetLog8Facility.GENERAL, "msg2")
        results = client.query(severity=NetLog8Severity.ALERT)
        assert len(results) == 1
        assert results[0].message == "alert1"

    def test_query_by_facility(self, client: NetLog8Client):
        client.info(NetLog8Facility.ROUTING, "r1")
        client.info(NetLog8Facility.DHCP8, "d1")
        client.info(NetLog8Facility.ROUTING, "r2")
        results = client.query(facility=NetLog8Facility.ROUTING)
        assert len(results) == 2

    def test_query_by_event_type(self, client: NetLog8Client):
        client.sec_alert(NetLog8Facility.SECURITY, "a1")
        client.e3_trap(NetLog8Facility.ROUTING, "e1")
        client.sec_alert(NetLog8Facility.SECURITY, "a2")
        results = client.query(event_type=SEC_ALERT)
        assert len(results) == 2

    def test_query_limit(self, client: NetLog8Client):
        for i in range(10):
            client.info(NetLog8Facility.GENERAL, f"msg-{i}")
        results = client.query(limit=3)
        assert len(results) == 3

    def test_query_combined(self, client: NetLog8Client):
        client.sec_alert(NetLog8Facility.SECURITY, "sec")
        client.sec_alert(NetLog8Facility.ROUTING, "route-alert")
        client.info(NetLog8Facility.SECURITY, "info-sec")
        results = client.query(
            severity=NetLog8Severity.ALERT,
            facility=NetLog8Facility.SECURITY,
        )
        assert len(results) == 1
        assert results[0].message == "sec"

    def test_query_empty(self, client: NetLog8Client):
        assert client.query() == []


# ---------------------------------------------------------------------------
# Properties & clear
# ---------------------------------------------------------------------------

class TestProperties:
    def test_source(self, client: NetLog8Client):
        assert client.source == "router-1"

    def test_endpoint(self, client: NetLog8Client):
        assert client.endpoint == "netlog.zone"

    def test_counters(self, client: NetLog8Client):
        client.info(NetLog8Facility.GENERAL, "m1")
        client.info(NetLog8Facility.GENERAL, "m2")
        client.sec_alert(NetLog8Facility.SECURITY, "a1")
        counters = client.counters
        assert counters["INFO"] == 2
        assert counters["ALERT"] == 1
        assert "DEBUG" not in counters

    def test_clear(self, client: NetLog8Client):
        client.info(NetLog8Facility.GENERAL, "m1")
        client.sec_alert(NetLog8Facility.SECURITY, "a1")
        client.clear()
        assert client.count == 0
        assert client.counters == {}

    def test_entries(self, client: NetLog8Client):
        client.info(NetLog8Facility.GENERAL, "m1")
        client.info(NetLog8Facility.GENERAL, "m2")
        assert len(client.entries) == 2
        assert client.entries[0].message == "m1"
