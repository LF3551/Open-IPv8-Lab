# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for interactive CLI for Zone Server management."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from ipv8lab.cli import zone_cli
from ipv8lab.cli.zone_cli import app

runner = CliRunner()


def _reset() -> None:
    """Reset module-level state between tests."""
    zone_cli._primary = None
    zone_cli._secondary = None
    zone_cli._zone_prefix = ""


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------

class TestInit:
    def setup_method(self) -> None:
        _reset()

    def test_init_default(self) -> None:
        result = runner.invoke(app, ["init"])
        assert result.exit_code == 0
        assert "127.1.0.0" in result.output

    def test_init_custom_prefix(self) -> None:
        result = runner.invoke(app, ["init", "--prefix", "127.2.0.0"])
        assert result.exit_code == 0
        assert "127.2.0.0" in result.output

    def test_init_json(self) -> None:
        result = runner.invoke(app, ["init", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["zone_prefix"] == "127.1.0.0"
        assert data["primary"]["host_octet"] == 254
        assert data["secondary"]["host_octet"] == 253

    def test_init_with_key(self) -> None:
        result = runner.invoke(app, ["init", "--key-id", "my-key", "--secret", "s3cret", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["oauth8_key_id"] == "my-key"


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

class TestStatus:
    def setup_method(self) -> None:
        _reset()
        runner.invoke(app, ["init"])

    def test_status(self) -> None:
        result = runner.invoke(app, ["status"])
        assert result.exit_code == 0
        assert "Zone Server Status" in result.output

    def test_status_json(self) -> None:
        result = runner.invoke(app, ["status", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "primary" in data
        assert "secondary" in data
        assert data["primary"]["role"] == "PRIMARY" or "services" in data["primary"]


# ---------------------------------------------------------------------------
# service-add / service-list
# ---------------------------------------------------------------------------

class TestServices:
    def setup_method(self) -> None:
        _reset()
        runner.invoke(app, ["init"])

    def test_add_service(self) -> None:
        result = runner.invoke(app, ["service-add", "DHCP8", "dhcp.127.1.0.0"])
        assert result.exit_code == 0
        assert "DHCP8" in result.output

    def test_add_service_json(self) -> None:
        result = runner.invoke(app, ["service-add", "DNS8", "dns.127.1.0.0", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["service_type"] == "DNS8"
        assert data["endpoint"] == "dns.127.1.0.0"

    def test_add_service_both(self) -> None:
        result = runner.invoke(app, ["service-add", "NTP8", "ntp.zone", "--role", "both", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "primary" in data["registered_on"]
        assert "secondary" in data["registered_on"]

    def test_add_service_invalid_type(self) -> None:
        result = runner.invoke(app, ["service-add", "INVALID", "x.x"])
        assert result.exit_code == 1

    def test_list_services_empty(self) -> None:
        result = runner.invoke(app, ["service-list"])
        assert result.exit_code == 0
        assert "No services" in result.output

    def test_list_services(self) -> None:
        runner.invoke(app, ["service-add", "DHCP8", "dhcp.zone"])
        result = runner.invoke(app, ["service-list"])
        assert result.exit_code == 0
        assert "DHCP8" in result.output

    def test_list_services_json(self) -> None:
        runner.invoke(app, ["service-add", "DHCP8", "dhcp.zone"])
        result = runner.invoke(app, ["service-list", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 1
        assert data[0]["type"] == "DHCP8"


# ---------------------------------------------------------------------------
# acl-add / acl-list / acl-check
# ---------------------------------------------------------------------------

class TestACL:
    def setup_method(self) -> None:
        _reset()
        runner.invoke(app, ["init"])

    def test_add_acl_rule(self) -> None:
        result = runner.invoke(app, ["acl-add", "dev-01", "gateway", "--action", "permit"])
        assert result.exit_code == 0
        assert "PERMIT" in result.output

    def test_add_acl_json(self) -> None:
        result = runner.invoke(app, ["acl-add", "*", "gateway", "--action", "permit", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["action"] == "PERMIT"

    def test_add_acl_invalid_action(self) -> None:
        result = runner.invoke(app, ["acl-add", "x", "y", "--action", "drop"])
        assert result.exit_code == 1

    def test_list_acl_empty(self) -> None:
        result = runner.invoke(app, ["acl-list"])
        assert result.exit_code == 0
        assert "No ACL8" in result.output

    def test_list_acl(self) -> None:
        runner.invoke(app, ["acl-add", "dev", "gw", "--action", "permit"])
        result = runner.invoke(app, ["acl-list"])
        assert result.exit_code == 0
        assert "PERMIT" in result.output

    def test_list_acl_json(self) -> None:
        runner.invoke(app, ["acl-add", "dev", "gw", "--action", "deny"])
        result = runner.invoke(app, ["acl-list", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 1
        assert data[0]["action"] == "DENY"

    def test_acl_check_permit(self) -> None:
        runner.invoke(app, ["acl-add", "*", "gateway", "--action", "permit"])
        result = runner.invoke(app, ["acl-check", "dev-01", "gateway"])
        assert result.exit_code == 0
        assert "PERMIT" in result.output

    def test_acl_check_deny(self) -> None:
        result = runner.invoke(app, ["acl-check", "dev-01", "other"])
        assert result.exit_code == 0
        assert "DENY" in result.output

    def test_acl_check_json(self) -> None:
        result = runner.invoke(app, ["acl-check", "x", "y", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "permitted" in data
        assert data["action"] == "DENY"


# ---------------------------------------------------------------------------
# oauth-issue / oauth-validate
# ---------------------------------------------------------------------------

class TestOAuth:
    def setup_method(self) -> None:
        _reset()
        runner.invoke(app, ["init"])

    def test_issue_token(self) -> None:
        result = runner.invoke(app, ["oauth-issue", "device-42"])
        assert result.exit_code == 0
        assert "device-42" in result.output

    def test_issue_token_json(self) -> None:
        result = runner.invoke(app, ["oauth-issue", "dev-1", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["subject"] == "dev-1"
        assert "token" in data

    def test_issue_and_validate(self) -> None:
        issue_result = runner.invoke(app, ["oauth-issue", "dev-1", "--json"])
        token = json.loads(issue_result.output)["token"]
        val_result = runner.invoke(app, ["oauth-validate", token])
        assert val_result.exit_code == 0
        assert "VALID" in val_result.output

    def test_validate_invalid_token(self) -> None:
        result = runner.invoke(app, ["oauth-validate", "bad.token.here"])
        assert result.exit_code == 0
        # Should show error status
        assert "UNKNOWN_KEY" in result.output or "MALFORMED" in result.output or "INVALID" in result.output

    def test_validate_json(self) -> None:
        issue_result = runner.invoke(app, ["oauth-issue", "dev-1", "--json"])
        token = json.loads(issue_result.output)["token"]
        val_result = runner.invoke(app, ["oauth-validate", token, "--json"])
        assert val_result.exit_code == 0
        data = json.loads(val_result.output)
        assert data["valid"] is True
        assert data["subject"] == "dev-1"

    def test_issue_bad_key(self) -> None:
        result = runner.invoke(app, ["oauth-issue", "dev", "--key-id", "no-such-key"])
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# oauth-key-add
# ---------------------------------------------------------------------------

class TestOAuthKeyAdd:
    def setup_method(self) -> None:
        _reset()
        runner.invoke(app, ["init"])

    def test_add_key(self) -> None:
        result = runner.invoke(app, ["oauth-key-add", "new-key", "new-secret"])
        assert result.exit_code == 0
        assert "new-key" in result.output

    def test_add_key_primary_only(self) -> None:
        result = runner.invoke(app, ["oauth-key-add", "k2", "s2", "--role", "primary"])
        assert result.exit_code == 0
        assert "primary" in result.output


# ---------------------------------------------------------------------------
# vlan-check
# ---------------------------------------------------------------------------

class TestVLANCheck:
    def setup_method(self) -> None:
        _reset()
        runner.invoke(app, ["init"])

    def test_even_vlan(self) -> None:
        result = runner.invoke(app, ["vlan-check", "100"])
        assert result.exit_code == 0
        assert "Primary" in result.output

    def test_odd_vlan(self) -> None:
        result = runner.invoke(app, ["vlan-check", "101"])
        assert result.exit_code == 0
        assert "Secondary" in result.output

    def test_vlan_json(self) -> None:
        result = runner.invoke(app, ["vlan-check", "100", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["vlan_id"] == 100
        assert data["primary_is_root"] is True
        assert data["root"] == "primary"

    def test_vlan_json_odd(self) -> None:
        result = runner.invoke(app, ["vlan-check", "99", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["root"] == "secondary"


# ---------------------------------------------------------------------------
# Auto-init (ensure_pair)
# ---------------------------------------------------------------------------

class TestAutoInit:
    def setup_method(self) -> None:
        _reset()

    def test_status_without_init(self) -> None:
        """Status should auto-create pair if not initialized."""
        result = runner.invoke(app, ["status", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "primary" in data
