# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for standalone NetLog8 protocol per draft-thain-netlog8-00."""

from __future__ import annotations

import json
import time

import pytest
from typer.testing import CliRunner

from ipv8lab.netlog8 import (
    NetLog8Entry,
    NetLog8Facility,
    NetLog8Severity,
)
from ipv8lab.netlog8_proto import (
    NETLOG8_MAGIC,
    AlertRule,
    NetLog8Collector,
    NetLog8Header,
    NetLog8Message,
    NetLog8Relay,
    RateLimiter,
    frame_entry,
)
from ipv8lab.cli.netlog8_proto_cli import app

runner = CliRunner()


def _make_entry(
    msg: str = "test",
    sev: NetLog8Severity = NetLog8Severity.INFO,
    fac: NetLog8Facility = NetLog8Facility.GENERAL,
    event_type: str = "INFO",
    source: str = "dev-1",
) -> NetLog8Entry:
    return NetLog8Entry(
        timestamp=time.time(),
        severity=sev,
        facility=fac,
        source=source,
        event_type=event_type,
        message=msg,
    )


# ===================================================================
# Header
# ===================================================================

class TestNetLog8Header:
    def test_pack_unpack(self) -> None:
        h = NetLog8Header(severity=3, facility=2, length=100)
        data = h.pack()
        assert len(data) == NetLog8Header.HEADER_SIZE
        h2 = NetLog8Header.unpack(data)
        assert h2.magic == NETLOG8_MAGIC
        assert h2.severity == 3
        assert h2.facility == 2
        assert h2.length == 100

    def test_invalid_magic(self) -> None:
        data = b"\x00\x00\x00\x00" + b"\x00" * (NetLog8Header.HEADER_SIZE - 4)
        with pytest.raises(ValueError, match="magic"):
            NetLog8Header.unpack(data)

    def test_too_short(self) -> None:
        with pytest.raises(ValueError, match="bytes"):
            NetLog8Header.unpack(b"\x00\x00")

    def test_header_size(self) -> None:
        assert NetLog8Header.HEADER_SIZE == 12


# ===================================================================
# frame_entry
# ===================================================================

class TestFrameEntry:
    def test_frame(self) -> None:
        entry = _make_entry("hello")
        msg = frame_entry(entry)
        assert isinstance(msg, NetLog8Message)
        assert msg.header.magic == NETLOG8_MAGIC
        assert msg.header.length == len("hello".encode())
        assert msg.entry is entry

    def test_to_dict(self) -> None:
        msg = frame_entry(_make_entry("x"))
        d = msg.to_dict()
        assert d["version"] == 1
        assert "severity" in d


# ===================================================================
# AlertRule
# ===================================================================

class TestAlertRule:
    def test_matches_severity(self) -> None:
        rule = AlertRule(name="critical", severity_min=NetLog8Severity.ERROR)
        assert rule.matches(_make_entry(sev=NetLog8Severity.ERROR))
        assert rule.matches(_make_entry(sev=NetLog8Severity.ALERT))
        assert not rule.matches(_make_entry(sev=NetLog8Severity.WARNING))

    def test_matches_event_type(self) -> None:
        rule = AlertRule(name="sec", severity_min=NetLog8Severity.DEBUG, event_types=("SEC-ALERT",))
        assert rule.matches(_make_entry(event_type="SEC-ALERT"))
        assert not rule.matches(_make_entry(event_type="INFO"))

    def test_matches_facility(self) -> None:
        rule = AlertRule(
            name="routing",
            severity_min=NetLog8Severity.DEBUG,
            facilities=(NetLog8Facility.ROUTING,),
        )
        assert rule.matches(_make_entry(fac=NetLog8Facility.ROUTING))
        assert not rule.matches(_make_entry(fac=NetLog8Facility.SECURITY))


# ===================================================================
# Collector — ingest
# ===================================================================

class TestCollectorIngest:
    def test_ingest_single(self) -> None:
        col = NetLog8Collector()
        col.ingest(_make_entry("test"))
        assert col.summary()["received"] == 1
        assert col.summary()["buffered"] == 1

    def test_ingest_multiple_sources(self) -> None:
        col = NetLog8Collector()
        col.ingest(_make_entry(source="a"))
        col.ingest(_make_entry(source="b"))
        assert sorted(col.summary()["sources"]) == ["a", "b"]

    def test_ingest_triggers_alert(self) -> None:
        col = NetLog8Collector()
        col.add_rule(AlertRule(name="sec", severity_min=NetLog8Severity.ALERT, event_types=("SEC-ALERT",)))
        alerts = col.ingest(_make_entry(sev=NetLog8Severity.ALERT, event_type="SEC-ALERT"))
        assert len(alerts) == 1
        assert alerts[0].rule_name == "sec"

    def test_ingest_no_alert(self) -> None:
        col = NetLog8Collector()
        col.add_rule(AlertRule(name="sec", severity_min=NetLog8Severity.ALERT, event_types=("SEC-ALERT",)))
        alerts = col.ingest(_make_entry(sev=NetLog8Severity.INFO))
        assert len(alerts) == 0

    def test_ingest_batch(self) -> None:
        col = NetLog8Collector()
        entries = [_make_entry(f"msg{i}") for i in range(5)]
        col.ingest_batch(entries)
        assert col.summary()["received"] == 5


# ===================================================================
# Collector — query
# ===================================================================

class TestCollectorQuery:
    def test_query_all(self) -> None:
        col = NetLog8Collector()
        for i in range(3):
            col.ingest(_make_entry(f"msg{i}"))
        assert len(col.query()) == 3

    def test_query_by_severity(self) -> None:
        col = NetLog8Collector()
        col.ingest(_make_entry(sev=NetLog8Severity.INFO))
        col.ingest(_make_entry(sev=NetLog8Severity.ERROR))
        results = col.query(severity=NetLog8Severity.ERROR)
        assert len(results) == 1

    def test_query_by_event_type(self) -> None:
        col = NetLog8Collector()
        col.ingest(_make_entry(event_type="SEC-ALERT", sev=NetLog8Severity.ALERT))
        col.ingest(_make_entry(event_type="INFO"))
        results = col.query(event_type="SEC-ALERT")
        assert len(results) == 1

    def test_query_by_source(self) -> None:
        col = NetLog8Collector()
        col.ingest(_make_entry(source="router-1"))
        col.ingest(_make_entry(source="router-2"))
        results = col.query(source="router-1")
        assert len(results) == 1

    def test_query_limit(self) -> None:
        col = NetLog8Collector()
        for i in range(10):
            col.ingest(_make_entry(f"msg{i}"))
        results = col.query(limit=3)
        assert len(results) == 3

    def test_query_alerts(self) -> None:
        col = NetLog8Collector()
        col.add_rule(AlertRule(name="r1", severity_min=NetLog8Severity.ALERT))
        col.ingest(_make_entry(sev=NetLog8Severity.ALERT))
        alerts = col.query_alerts()
        assert len(alerts) == 1


# ===================================================================
# Collector — export
# ===================================================================

class TestCollectorExport:
    def test_export_jsonl(self) -> None:
        col = NetLog8Collector()
        col.ingest(_make_entry("a"))
        col.ingest(_make_entry("b"))
        data = col.export_jsonl()
        assert len(data) == 2
        assert data[0]["message"] == "a"

    def test_export_jsonl_limit(self) -> None:
        col = NetLog8Collector()
        for i in range(5):
            col.ingest(_make_entry(f"m{i}"))
        data = col.export_jsonl(limit=2)
        assert len(data) == 2

    def test_export_syslog(self) -> None:
        col = NetLog8Collector()
        col.ingest(_make_entry("hello"))
        lines = col.export_syslog()
        assert len(lines) == 1
        assert "hello" in lines[0]
        assert lines[0].startswith("<")


# ===================================================================
# Collector — housekeeping
# ===================================================================

class TestCollectorHousekeeping:
    def test_clear_alerts(self) -> None:
        col = NetLog8Collector()
        col.add_rule(AlertRule(name="r1", severity_min=NetLog8Severity.ALERT))
        col.ingest(_make_entry(sev=NetLog8Severity.ALERT))
        n = col.clear_alerts()
        assert n == 1
        assert len(col.alerts) == 0

    def test_clear_buffer(self) -> None:
        col = NetLog8Collector()
        col.ingest(_make_entry())
        n = col.clear_buffer()
        assert n == 1
        assert col.summary()["buffered"] == 0

    def test_clear_rules(self) -> None:
        col = NetLog8Collector()
        col.add_rule(AlertRule(name="r1"))
        n = col.clear_rules()
        assert n == 1


# ===================================================================
# Relay
# ===================================================================

class TestRelay:
    def test_forward_to_collector(self) -> None:
        col = NetLog8Collector()
        relay = NetLog8Relay()
        relay.add_collector(col)
        relay.forward(_make_entry("msg"))
        assert col.summary()["received"] == 1
        assert relay.summary()["forwarded"] == 1

    def test_forward_batch(self) -> None:
        col = NetLog8Collector()
        relay = NetLog8Relay()
        relay.add_collector(col)
        entries = [_make_entry(f"m{i}") for i in range(3)]
        relay.forward_batch(entries)
        assert col.summary()["received"] == 3

    def test_multi_collector(self) -> None:
        c1 = NetLog8Collector(collector_id="c1")
        c2 = NetLog8Collector(collector_id="c2")
        relay = NetLog8Relay()
        relay.add_collector(c1)
        relay.add_collector(c2)
        relay.forward(_make_entry())
        assert c1.summary()["received"] == 1
        assert c2.summary()["received"] == 1


# ===================================================================
# RateLimiter
# ===================================================================

class TestRateLimiter:
    def test_allow_within_burst(self) -> None:
        rl = RateLimiter(rate=10, burst=5)
        now = time.time()
        for _ in range(5):
            assert rl.allow(now=now)

    def test_drop_over_burst(self) -> None:
        rl = RateLimiter(rate=10, burst=3)
        now = time.time()
        for _ in range(3):
            rl.allow(now=now)
        assert not rl.allow(now=now)

    def test_refill(self) -> None:
        rl = RateLimiter(rate=10, burst=5)
        now = time.time()
        for _ in range(5):
            rl.allow(now=now)
        assert not rl.allow(now=now)
        assert rl.allow(now=now + 1.0)  # 10 tokens refilled

    def test_summary(self) -> None:
        rl = RateLimiter()
        d = rl.summary()
        assert "rate" in d
        assert "dropped" in d


# ===================================================================
# CLI tests
# ===================================================================

class TestNetLog8ProtoCLI:
    def test_init_json(self) -> None:
        result = runner.invoke(app, ["init", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "client" in data

    def test_log_json(self) -> None:
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["log", "test message", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["message"] == "test message"

    def test_sec_alert_json(self) -> None:
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["sec-alert", "prefix violation", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["event_type"] == "SEC-ALERT"

    def test_e3_trap_json(self) -> None:
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["e3-trap", "interior link violation", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["event_type"] == "E3"

    def test_query_json(self) -> None:
        runner.invoke(app, ["init"])
        runner.invoke(app, ["log", "msg1"])
        result = runner.invoke(app, ["query", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) >= 1

    def test_add_rule_json(self) -> None:
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["add-rule", "sec-rule", "--event-types", "SEC-ALERT", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["name"] == "sec-rule"

    def test_alerts_json(self) -> None:
        runner.invoke(app, ["init"])
        runner.invoke(app, ["add-rule", "sec-rule", "--severity", "ALERT", "--event-types", "SEC-ALERT"])
        runner.invoke(app, ["sec-alert", "violation"])
        result = runner.invoke(app, ["alerts", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) >= 1

    def test_export_jsonl_json(self) -> None:
        runner.invoke(app, ["init"])
        runner.invoke(app, ["log", "export test"])
        result = runner.invoke(app, ["export", "--fmt", "jsonl", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["format"] == "jsonl"

    def test_export_syslog_json(self) -> None:
        runner.invoke(app, ["init"])
        runner.invoke(app, ["log", "syslog test"])
        result = runner.invoke(app, ["export", "--fmt", "syslog", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["format"] == "syslog"

    def test_header_info_json(self) -> None:
        result = runner.invoke(app, ["header-info", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["header_size"] == 12

    def test_status_json(self) -> None:
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["status", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "received" in data

    def test_no_args_help(self) -> None:
        result = runner.invoke(app, [])
        assert result.exit_code in (0, 2)
