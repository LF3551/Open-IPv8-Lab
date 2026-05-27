# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for end-to-end integration scenario."""

import pytest

from ipv8lab.address import IPv8Address
from ipv8lab.integration import (
    EndToEndScenario,
    IntegrationResult,
    StepResult,
    ZoneConfig,
)
from ipv8lab.netlog8 import SEC_ALERT
from ipv8lab.zoneserver import ACL8Action, ACL8Rule


class _FakeClock:
    def __init__(self, now: float = 1_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


# ---------------------------------------------------------------------------
# StepResult / IntegrationResult
# ---------------------------------------------------------------------------

class TestStepResult:
    def test_fields(self):
        r = StepResult(step="test", success=True, detail="ok")
        assert r.step == "test"
        assert r.success is True

    def test_integration_result_all_passed(self):
        ir = IntegrationResult()
        ir.add("a", True)
        ir.add("b", True)
        assert ir.all_passed

    def test_integration_result_failed(self):
        ir = IntegrationResult()
        ir.add("a", True)
        ir.add("b", False, "bad")
        assert not ir.all_passed
        assert len(ir.failed_steps) == 1


# ---------------------------------------------------------------------------
# Full happy-path scenario
# ---------------------------------------------------------------------------

class TestFullScenario:
    @pytest.fixture()
    def clock(self) -> _FakeClock:
        return _FakeClock()

    @pytest.fixture()
    def scenario(self, clock: _FakeClock) -> EndToEndScenario:
        return EndToEndScenario(clock=clock)

    def test_full_scenario_passes(self, scenario: EndToEndScenario, clock: _FakeClock):
        result = scenario.run_full_scenario(client_id="laptop-1", now=clock.now)
        assert result.all_passed, [s for s in result.steps if not s.success]
        assert len(result.steps) == 7

    def test_step_names(self, scenario: EndToEndScenario, clock: _FakeClock):
        result = scenario.run_full_scenario(now=clock.now)
        names = [s.step for s in result.steps]
        assert names == [
            "zone_setup",
            "dhcp8_provision",
            "oauth8_auth",
            "acl8_authorize",
            "whois8_validate",
            "routing",
            "ingress_filter",
        ]

    def test_netlog_entries(self, scenario: EndToEndScenario, clock: _FakeClock):
        scenario.run_full_scenario(now=clock.now)
        assert scenario.logger.count >= 7

    def test_cross_asn_scenario(self, clock: _FakeClock):
        cfg = ZoneConfig(asn=64496)
        s = EndToEndScenario(config=cfg, clock=clock)
        result = s.run_full_scenario(
            client_id="server-1",
            destination_asn=64497,
            now=clock.now,
        )
        assert result.all_passed


# ---------------------------------------------------------------------------
# Individual step tests
# ---------------------------------------------------------------------------

class TestZoneSetup:
    def test_setup_creates_zone_servers(self):
        s = EndToEndScenario(clock=_FakeClock())
        s.setup_zone()
        assert s._primary is not None
        assert s._secondary is not None
        assert s._primary.service_count == 4
        assert s._dhcp_server is not None
        assert s._whois8 is not None

    def test_setup_result(self):
        s = EndToEndScenario(clock=_FakeClock())
        r = s.setup_zone()
        assert r.success
        assert "127.1.0.0" in r.detail


class TestDHCP8Provision:
    def test_provision_success(self):
        s = EndToEndScenario(clock=_FakeClock())
        s.setup_zone()
        r = s.provision_device("d1")
        assert r.success
        assert "d1" in r.detail

    def test_provision_without_setup(self):
        s = EndToEndScenario()
        r = s.provision_device("d1")
        assert not r.success
        assert "not setup" in r.detail

    def test_provision_pool_exhausted(self):
        cfg = ZoneConfig()
        s = EndToEndScenario(config=cfg, clock=_FakeClock())
        s.setup_zone()
        # Exhaust pool
        assert s._dhcp_server is not None
        s._dhcp_server.pool._next = s._dhcp_server.pool.end + 1
        r = s.provision_device("d-late")
        assert not r.success
        assert "exhausted" in r.detail


class TestOAuth8Auth:
    def test_auth_success(self):
        clock = _FakeClock()
        s = EndToEndScenario(clock=clock)
        s.setup_zone()
        r = s.authenticate_device("d1", now=clock.now)
        assert r.success

    def test_auth_without_setup(self):
        s = EndToEndScenario()
        r = s.authenticate_device("d1")
        assert not r.success


class TestACL8Authorize:
    def test_permit(self):
        s = EndToEndScenario(clock=_FakeClock())
        s.setup_zone()
        assert s._primary is not None
        s._primary.acl8_engine.add_rule(ACL8Rule(
            source="d1", destination="gw", action=ACL8Action.PERMIT,
        ))
        r = s.authorize_traffic("d1", "gw")
        assert r.success
        assert "PERMIT" in r.detail

    def test_deny_lateral(self):
        s = EndToEndScenario(clock=_FakeClock())
        s.setup_zone()
        r = s.authorize_traffic("d1", "d2")
        assert not r.success
        assert "DENIED" in r.detail

    def test_deny_logs_sec_alert(self):
        s = EndToEndScenario(clock=_FakeClock())
        s.setup_zone()
        s.authorize_traffic("d1", "d2")
        alerts = s.logger.query(event_type=SEC_ALERT)
        assert len(alerts) >= 1


class TestWHOIS8Validate:
    def test_valid_destination(self):
        s = EndToEndScenario(clock=_FakeClock())
        s.setup_zone()
        dst = IPv8Address.parse("64496-192.0.2.100")
        r = s.validate_egress(dst)
        assert r.success

    def test_unknown_asn(self):
        s = EndToEndScenario(clock=_FakeClock())
        s.setup_zone()
        dst = IPv8Address.parse("12345.10.0.0.1")
        r = s.validate_egress(dst)
        assert not r.success
        assert "DENIED" in r.detail

    def test_reserved_range(self):
        s = EndToEndScenario(clock=_FakeClock())
        s.setup_zone()
        dst = IPv8Address.parse("127.1.0.0.10.0.0.1")
        r = s.validate_egress(dst)
        assert not r.success

    def test_ipv4_compatible_bypass(self):
        s = EndToEndScenario(clock=_FakeClock())
        s.setup_zone()
        dst = IPv8Address.parse("0.0.0.0.8.8.8.8")
        r = s.validate_egress(dst)
        assert r.success


class TestRouting:
    def test_route_found(self):
        s = EndToEndScenario(clock=_FakeClock())
        s.setup_zone()
        src = IPv8Address.parse("64496-192.0.2.10")
        dst = IPv8Address.parse("64496-192.0.2.100")
        r = s.route_packet(src, dst)
        assert r.success
        assert "via" in r.detail

    def test_no_route(self):
        s = EndToEndScenario(clock=_FakeClock())
        s.setup_zone()
        src = IPv8Address.parse("64496-192.0.2.10")
        dst = IPv8Address.parse("99999.10.0.0.1")
        r = s.route_packet(src, dst)
        assert not r.success


class TestIngressFilter:
    def test_clean_packet(self):
        s = EndToEndScenario(clock=_FakeClock())
        s.setup_zone()
        src = IPv8Address.parse("64496-192.0.2.10")
        dst = IPv8Address.parse("64496-192.0.2.100")
        r = s.check_ingress(src, dst)
        assert r.success

    def test_spoofed_source(self):
        s = EndToEndScenario(clock=_FakeClock())
        s.setup_zone()
        src = IPv8Address.parse("99999.10.0.0.1")  # wrong ASN
        dst = IPv8Address.parse("64496-192.0.2.100")
        r = s.check_ingress(src, dst)
        assert not r.success


# ---------------------------------------------------------------------------
# Custom config
# ---------------------------------------------------------------------------

class TestCustomConfig:
    def test_custom_asn(self):
        cfg = ZoneConfig(asn=64497, whois8_holder="Acme", whois8_country="DE")
        clock = _FakeClock()
        s = EndToEndScenario(config=cfg, clock=clock)
        result = s.run_full_scenario(now=clock.now)
        assert result.all_passed

    def test_custom_network_prefix(self):
        cfg = ZoneConfig(network_prefix=(10, 0, 1))
        clock = _FakeClock()
        s = EndToEndScenario(config=cfg, clock=clock)
        result = s.run_full_scenario(now=clock.now)
        assert result.all_passed
