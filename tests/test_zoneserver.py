# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for Zone Server mock (OAuth8 cache, ACL8)."""

import pytest

from ipv8lab.zoneserver import (
    ACL8Action,
    ACL8Engine,
    ACL8Layer,
    ACL8Rule,
    ClaimsACL8Engine,
    ClaimsACLRule,
    JWTAuditEvent,
    JWTClaimsContext,
    OAuth8AAASubstrate,
    OAuth8Cache,
    TokenStatus,
    ZoneServer,
    ZoneServerRole,
    ZoneService,
    ZoneServiceType,
    make_zone_server_pair,
)


# ---------------------------------------------------------------------------
# OAuth8Cache
# ---------------------------------------------------------------------------

class TestOAuth8Cache:
    @pytest.fixture()
    def cache(self) -> OAuth8Cache:
        c = OAuth8Cache()
        c.register_key("k1", b"supersecret")
        return c

    def test_register_and_count(self, cache: OAuth8Cache):
        assert cache.key_count == 1
        cache.register_key("k2", b"another")
        assert cache.key_count == 2

    def test_unregister_key(self, cache: OAuth8Cache):
        cache.unregister_key("k1")
        assert cache.key_count == 0

    def test_unregister_missing(self, cache: OAuth8Cache):
        with pytest.raises(KeyError, match="not in cache"):
            cache.unregister_key("nope")

    def test_issue_and_validate(self, cache: OAuth8Cache):
        now = 1_000_000.0
        raw = cache.issue_token(
            key_id="k1",
            subject="device-1",
            issuer="zone-server",
            audience="zone-a",
            duration=3600,
            scopes=("admin", "read"),
            now=now,
        )
        result = cache.validate_token(raw, now=now + 10)
        assert result.is_valid
        assert result.token is not None
        assert result.token.subject == "device-1"
        assert result.token.issuer == "zone-server"
        assert result.token.audience == "zone-a"
        assert result.token.scopes == ("admin", "read")
        assert result.token.issued_at == now
        assert result.token.expires_at == now + 3600

    def test_expired_token(self, cache: OAuth8Cache):
        now = 1_000_000.0
        raw = cache.issue_token("k1", "d1", "iss", "aud", duration=100, now=now)
        result = cache.validate_token(raw, now=now + 200)
        assert result.status == TokenStatus.EXPIRED
        assert result.token is not None
        assert result.token.is_expired(now + 200)

    def test_invalid_signature(self, cache: OAuth8Cache):
        now = 1_000_000.0
        raw = cache.issue_token("k1", "d1", "iss", "aud", now=now)
        tampered = raw[:-5] + "XXXXX"
        result = cache.validate_token(tampered, now=now)
        assert result.status == TokenStatus.INVALID_SIGNATURE

    def test_unknown_key(self, cache: OAuth8Cache):
        now = 1_000_000.0
        raw = cache.issue_token("k1", "d1", "iss", "aud", now=now)
        cache.unregister_key("k1")
        result = cache.validate_token(raw, now=now)
        assert result.status == TokenStatus.UNKNOWN_KEY

    def test_malformed_token(self, cache: OAuth8Cache):
        result = cache.validate_token("not.a.valid.jwt.at.all")
        assert result.status == TokenStatus.MALFORMED

    def test_malformed_two_parts(self, cache: OAuth8Cache):
        result = cache.validate_token("only.two")
        assert result.status == TokenStatus.MALFORMED

    def test_revoke_token(self, cache: OAuth8Cache):
        now = 1_000_000.0
        raw = cache.issue_token("k1", "d1", "iss", "aud", now=now)
        cache.revoke_token(raw)
        result = cache.validate_token(raw, now=now)
        assert result.status == TokenStatus.INVALID_SIGNATURE
        assert "revoked" in result.reason

    def test_issue_unknown_key(self, cache: OAuth8Cache):
        with pytest.raises(KeyError, match="not in cache"):
            cache.issue_token("nope", "d1", "iss", "aud")

    def test_no_scopes(self, cache: OAuth8Cache):
        now = 1_000_000.0
        raw = cache.issue_token("k1", "d1", "iss", "aud", now=now)
        result = cache.validate_token(raw, now=now)
        assert result.is_valid
        assert result.token is not None
        assert result.token.scopes == ()


# ---------------------------------------------------------------------------
# ACL8Engine
# ---------------------------------------------------------------------------

class TestACL8Engine:
    @pytest.fixture()
    def engine(self) -> ACL8Engine:
        e = ACL8Engine()
        e.add_rule(ACL8Rule(
            source="device-1",
            destination="gateway",
            action=ACL8Action.PERMIT,
            description="device to gateway",
        ))
        e.add_rule(ACL8Rule(
            source="device-1",
            destination="*",
            action=ACL8Action.DENY,
            description="deny all other from device-1",
        ))
        return e

    def test_permit(self, engine: ACL8Engine):
        result = engine.evaluate("device-1", "gateway")
        assert result.is_permitted
        assert result.matched_rule is not None

    def test_deny_lateral(self, engine: ACL8Engine):
        result = engine.evaluate("device-1", "device-2")
        assert not result.is_permitted
        assert "deny all other" in result.reason

    def test_default_deny(self, engine: ACL8Engine):
        result = engine.evaluate("unknown", "anywhere")
        assert not result.is_permitted
        assert "default deny" in result.reason

    def test_default_permit(self):
        e = ACL8Engine(default_action=ACL8Action.PERMIT)
        result = e.evaluate("any", "any")
        assert result.is_permitted
        assert "default permit" in result.reason

    def test_wildcard_source(self):
        e = ACL8Engine()
        e.add_rule(ACL8Rule(source="*", destination="dns8", action=ACL8Action.PERMIT))
        assert e.evaluate("anyone", "dns8").is_permitted

    def test_remove_rule(self, engine: ACL8Engine):
        removed = engine.remove_rule(0)
        assert removed.description == "device to gateway"
        assert engine.rule_count == 1

    def test_list_rules(self, engine: ACL8Engine):
        rules = engine.list_rules()
        assert len(rules) == 2
        assert rules[0].action == ACL8Action.PERMIT

    def test_rule_count(self, engine: ACL8Engine):
        assert engine.rule_count == 2

    def test_first_match_wins(self):
        e = ACL8Engine()
        e.add_rule(ACL8Rule(source="d1", destination="gw", action=ACL8Action.PERMIT))
        e.add_rule(ACL8Rule(source="d1", destination="gw", action=ACL8Action.DENY))
        assert e.evaluate("d1", "gw").is_permitted

    def test_layer_attribute(self):
        rule = ACL8Rule(
            source="d1", destination="gw",
            layer=ACL8Layer.NIC_FIRMWARE,
        )
        assert rule.layer == ACL8Layer.NIC_FIRMWARE

    def test_all_layers(self):
        layers = {layer.name for layer in ACL8Layer}
        assert layers == {"NIC_FIRMWARE", "ZONE_SERVER_GATEWAY", "SWITCH_PORT_OAUTH2"}


# ---------------------------------------------------------------------------
# ZoneServer
# ---------------------------------------------------------------------------

class TestZoneServer:
    @pytest.fixture()
    def primary(self) -> ZoneServer:
        zs = ZoneServer(role=ZoneServerRole.PRIMARY, zone_prefix="127.1.0.0")
        zs.oauth8_cache.register_key("k1", b"secret")
        zs.acl8_engine.add_rule(ACL8Rule(
            source="device-1", destination="gateway",
            action=ACL8Action.PERMIT,
        ))
        return zs

    def test_primary_host_octet(self, primary: ZoneServer):
        assert primary.host_octet == 254

    def test_secondary_host_octet(self):
        zs = ZoneServer(role=ZoneServerRole.SECONDARY)
        assert zs.host_octet == 253

    def test_pvrst_root_even(self, primary: ZoneServer):
        assert primary.is_root_for_vlan(100)
        assert not primary.is_root_for_vlan(101)

    def test_pvrst_root_odd(self):
        zs = ZoneServer(role=ZoneServerRole.SECONDARY)
        assert zs.is_root_for_vlan(101)
        assert not zs.is_root_for_vlan(100)

    def test_register_and_list_services(self, primary: ZoneServer):
        primary.register_service(ZoneService(ZoneServiceType.DNS8, "dns.zone"))
        primary.register_service(ZoneService(ZoneServiceType.NTP8, "ntp.zone"))
        assert primary.service_count == 2
        types = {s.service_type for s in primary.list_services()}
        assert types == {ZoneServiceType.DNS8, ZoneServiceType.NTP8}

    def test_get_service(self, primary: ZoneServer):
        primary.register_service(ZoneService(ZoneServiceType.DHCP8, "dhcp.zone"))
        svc = primary.get_service(ZoneServiceType.DHCP8)
        assert svc is not None
        assert svc.endpoint == "dhcp.zone"
        assert primary.get_service(ZoneServiceType.XLATE8) is None

    def test_authenticate_device(self, primary: ZoneServer):
        now = 1_000_000.0
        raw = primary.oauth8_cache.issue_token("k1", "d1", "iss", "aud", now=now)
        result = primary.authenticate_device(raw, now=now)
        assert result.is_valid

    def test_authorize_traffic(self, primary: ZoneServer):
        assert primary.authorize_traffic("device-1", "gateway").is_permitted
        assert not primary.authorize_traffic("device-1", "device-2").is_permitted

    def test_all_service_types(self):
        names = {s.name for s in ZoneServiceType}
        assert names == {"DHCP8", "DNS8", "NTP8", "NETLOG8", "OAUTH8", "WHOIS8", "ACL8", "XLATE8"}

    def test_service_enabled_default(self):
        svc = ZoneService(ZoneServiceType.DNS8, "dns.zone")
        assert svc.enabled is True

    def test_service_disabled(self):
        svc = ZoneService(ZoneServiceType.DNS8, "dns.zone", enabled=False)
        assert svc.enabled is False


class TestMakeZoneServerPair:
    def test_pair(self):
        primary, secondary = make_zone_server_pair("127.1.0.0")
        assert primary.role == ZoneServerRole.PRIMARY
        assert secondary.role == ZoneServerRole.SECONDARY
        assert primary.zone_prefix == "127.1.0.0"
        assert secondary.zone_prefix == "127.1.0.0"
        assert primary.host_octet == 254
        assert secondary.host_octet == 253

    def test_independent_caches(self):
        p, s = make_zone_server_pair()
        p.oauth8_cache.register_key("pk", b"p-secret")
        assert p.oauth8_cache.key_count == 1
        assert s.oauth8_cache.key_count == 0

    def test_independent_acl(self):
        p, s = make_zone_server_pair()
        p.acl8_engine.add_rule(ACL8Rule(source="a", destination="b"))
        assert p.acl8_engine.rule_count == 1
        assert s.acl8_engine.rule_count == 0


# ===========================================================================
# Step 13 — Identity-Driven Access Control
# ===========================================================================

def _make_aaa() -> tuple[OAuth8AAASubstrate, OAuth8Cache]:
    """Return an AAA substrate with a pre-registered key."""
    cache = OAuth8Cache()
    cache.register_key("k1", b"secret")
    aaa = OAuth8AAASubstrate(oauth8=cache)
    return aaa, cache


class TestClaimsACL8Engine:
    """ACL8 evaluates JWT claims, not port state."""

    def test_permit_matching_role(self):
        eng = ClaimsACL8Engine()
        eng.add_rule(ClaimsACLRule(required_role="admin", action=ACL8Action.PERMIT))
        claims = JWTClaimsContext("dev1", frozenset({"admin"}), frozenset())
        result = eng.evaluate(claims, "src", "dst")
        assert result.is_permitted

    def test_deny_missing_role(self):
        eng = ClaimsACL8Engine()
        eng.add_rule(ClaimsACLRule(required_role="admin", action=ACL8Action.PERMIT))
        claims = JWTClaimsContext("dev1", frozenset({"user"}), frozenset())
        result = eng.evaluate(claims, "src", "dst")
        assert not result.is_permitted

    def test_permit_matching_group(self):
        eng = ClaimsACL8Engine()
        eng.add_rule(ClaimsACLRule(required_group="zone-a", action=ACL8Action.PERMIT))
        claims = JWTClaimsContext("dev1", frozenset(), frozenset({"zone-a"}))
        assert eng.evaluate(claims, "*", "*").is_permitted

    def test_default_deny_no_rules(self):
        eng = ClaimsACL8Engine()
        claims = JWTClaimsContext("dev1", frozenset({"admin"}), frozenset())
        assert not eng.evaluate(claims, "src", "dst").is_permitted

    def test_explicit_deny_rule(self):
        eng = ClaimsACL8Engine(default_action=ACL8Action.PERMIT)
        eng.add_rule(ClaimsACLRule(source_pattern="bad", action=ACL8Action.DENY))
        claims = JWTClaimsContext("bad-dev", frozenset(), frozenset())
        assert not eng.evaluate(claims, "bad", "dst").is_permitted

    def test_rule_count(self):
        eng = ClaimsACL8Engine()
        assert eng.rule_count == 0
        eng.add_rule(ClaimsACLRule())
        assert eng.rule_count == 1

    def test_no_role_or_group_required_matches_any(self):
        eng = ClaimsACL8Engine()
        eng.add_rule(ClaimsACLRule(action=ACL8Action.PERMIT))
        claims = JWTClaimsContext("dev1", frozenset(), frozenset())
        assert eng.evaluate(claims, "src", "dst").is_permitted


class TestOAuth8AAASubstrate:
    """OAuth8AAASubstrate — session lifecycle and NetLog8 audit policy."""

    def test_start_session_valid_token(self):
        aaa, cache = _make_aaa()
        token = cache.issue_token("k1", "dev1", duration=3600)
        result = aaa.start_session("dev1", token)
        assert result.is_valid
        assert aaa.active_sessions == 1

    def test_start_session_invalid_token_logged_as_failure(self):
        aaa, _ = _make_aaa()
        aaa.start_session("dev1", "bad.token.here")
        assert len(aaa.audit_events_of_type(JWTAuditEvent.FAILURE)) == 1

    def test_issuance_logged_on_valid_session(self):
        aaa, cache = _make_aaa()
        token = cache.issue_token("k1", "dev1", duration=3600)
        aaa.start_session("dev1", token)
        assert len(aaa.audit_events_of_type(JWTAuditEvent.ISSUANCE)) == 1

    # ------------------------------------------------------------------
    # KEY REGRESSION: NetLog8 MUST be silent on a successful JWT check
    # ------------------------------------------------------------------

    def test_routine_check_does_not_emit_netlog8(self):
        """NetLog8 MUST NOT emit on a successful mid-session JWT check.

        This is the regression test required by Step 13: routine JWT
        presentations are silenced.  Only issuance and failures are logged.
        """
        aaa, cache = _make_aaa()
        token = cache.issue_token("k1", "dev1", duration=3600)
        aaa.start_session("dev1", token)

        aaa.acl.add_rule(ClaimsACLRule(action=ACL8Action.PERMIT))
        # Perform 5 successful mid-session checks
        for _ in range(5):
            aaa.check_access("dev1", "src", "dst", raw_token=token)

        # Only the single ISSUANCE event must exist — zero ROUTINE events
        routine_events = aaa.audit_events_of_type(JWTAuditEvent.ROUTINE)
        assert len(routine_events) == 0, (
            "NetLog8 must NOT emit on routine JWT presentations"
        )
        assert len(aaa.audit_events_of_type(JWTAuditEvent.ISSUANCE)) == 1

    def test_check_access_denied_on_expired_token(self):
        aaa, cache = _make_aaa()
        token = cache.issue_token("k1", "dev1", duration=1, now=0.0)
        aaa.start_session("dev1", token, now=0.0)
        result = aaa.check_access("dev1", "src", "dst", raw_token=token, now=9999.0)
        assert not result.is_permitted

    def test_failure_logged_on_expired_token_check(self):
        aaa, cache = _make_aaa()
        token = cache.issue_token("k1", "dev1", duration=1, now=0.0)
        aaa.start_session("dev1", token, now=0.0)
        aaa.check_access("dev1", "src", "dst", raw_token=token, now=9999.0)
        assert len(aaa.audit_events_of_type(JWTAuditEvent.FAILURE)) >= 1

    def test_check_access_no_active_session(self):
        aaa, _ = _make_aaa()
        result = aaa.check_access("ghost", "src", "dst")
        assert not result.is_permitted

    def test_end_session_removes_session(self):
        aaa, cache = _make_aaa()
        token = cache.issue_token("k1", "dev1", duration=3600)
        aaa.start_session("dev1", token)
        assert aaa.end_session("dev1")
        assert aaa.active_sessions == 0

    def test_end_session_nonexistent_returns_false(self):
        aaa, _ = _make_aaa()
        assert not aaa.end_session("ghost")

    def test_claims_roles_from_token(self):
        aaa, cache = _make_aaa()
        token = cache.issue_token("k1", "dev1", duration=3600,
                                  extra_claims={"roles": ["admin", "viewer"]})
        aaa.start_session("dev1", token)
        aaa.acl.add_rule(ClaimsACLRule(required_role="admin", action=ACL8Action.PERMIT))
        result = aaa.check_access("dev1", "src", "dst")
        assert result.is_permitted

    def test_claims_groups_from_token(self):
        aaa, cache = _make_aaa()
        token = cache.issue_token("k1", "dev1", duration=3600,
                                  extra_claims={"groups": ["zone-prod"]})
        aaa.start_session("dev1", token)
        aaa.acl.add_rule(ClaimsACLRule(required_group="zone-prod", action=ACL8Action.PERMIT))
        result = aaa.check_access("dev1", "src", "dst")
        assert result.is_permitted

    def test_multiple_sessions_independent(self):
        aaa, cache = _make_aaa()
        t1 = cache.issue_token("k1", "dev1", duration=3600)
        t2 = cache.issue_token("k1", "dev2", duration=3600)
        aaa.start_session("dev1", t1)
        aaa.start_session("dev2", t2)
        assert aaa.active_sessions == 2
        aaa.end_session("dev1")
        assert aaa.active_sessions == 1
