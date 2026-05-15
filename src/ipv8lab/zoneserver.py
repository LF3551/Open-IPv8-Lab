# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Zone Server mock per draft-thain-ipv8-02 Section 1.3.

The Zone Server is the central operational concept in IPv8 — a paired
active/active platform that runs every service a network segment
requires.  Primary Zone Server is at .254, Secondary at .253.

This module implements:
- OAuth8 cache: local JWT validation without round-trips to external
  identity providers.  Holds public keys, validates signatures locally.
- ACL8: east-west access control enforcement.  Devices communicate only
  with their designated service gateway.  Three enforcement layers:
  NIC firmware ACL8, Zone Server gateway ACL8, switch port OAuth2
  hardware VLAN enforcement.
- Zone Server service registry: DHCP8, DNS8, NTP8, NetLog8, OAuth8,
  WHOIS8, ACL8, XLATE8 — all unified into a single platform.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any


# ---------------------------------------------------------------------------
# OAuth8 cache
# ---------------------------------------------------------------------------

class TokenStatus(Enum):
    """JWT token validation status."""

    VALID = auto()
    EXPIRED = auto()
    INVALID_SIGNATURE = auto()
    UNKNOWN_KEY = auto()
    MALFORMED = auto()


@dataclass(frozen=True, slots=True)
class OAuth8Token:
    """Decoded JWT token for OAuth8."""

    subject: str
    issuer: str
    audience: str
    issued_at: float
    expires_at: float
    scopes: tuple[str, ...] = ()
    raw: str = ""

    def is_expired(self, now: float | None = None) -> bool:
        if now is None:
            now = time.time()
        return now >= self.expires_at


@dataclass(frozen=True, slots=True)
class TokenValidationResult:
    """Result of OAuth8 token validation."""

    status: TokenStatus
    token: OAuth8Token | None = None
    reason: str = ""

    @property
    def is_valid(self) -> bool:
        return self.status == TokenStatus.VALID


def _b64url_encode(data: bytes) -> str:
    return urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return urlsafe_b64decode(s)


class OAuth8Cache:
    """Local OAuth8 JWT cache per Section 1.3.

    Validates JWT signatures locally in sub-millisecond time without
    round-trips to external identity providers.  Uses HMAC-SHA256 for
    mock purposes (real deployments use RS256/ES256).
    """

    def __init__(self) -> None:
        self._keys: dict[str, bytes] = {}  # key_id → secret
        self._revoked: set[str] = set()

    def register_key(self, key_id: str, secret: bytes) -> None:
        """Register a signing key (public key equivalent for mock)."""
        self._keys[key_id] = secret

    def unregister_key(self, key_id: str) -> None:
        if key_id not in self._keys:
            raise KeyError(f"key {key_id!r} not in cache")
        del self._keys[key_id]

    def revoke_token(self, raw_token: str) -> None:
        """Add token to revocation set."""
        self._revoked.add(raw_token)

    def issue_token(
        self,
        key_id: str,
        subject: str,
        issuer: str,
        audience: str,
        duration: int = 3600,
        scopes: tuple[str, ...] = (),
        now: float | None = None,
    ) -> str:
        """Issue a mock JWT token signed with the given key."""
        if key_id not in self._keys:
            raise KeyError(f"key {key_id!r} not in cache")
        if now is None:
            now = time.time()
        header = {"alg": "HS256", "typ": "JWT", "kid": key_id}
        payload: dict[str, Any] = {
            "sub": subject,
            "iss": issuer,
            "aud": audience,
            "iat": now,
            "exp": now + duration,
        }
        if scopes:
            payload["scopes"] = list(scopes)
        h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        signing_input = f"{h}.{p}"
        sig = hmac.new(self._keys[key_id], signing_input.encode(), hashlib.sha256).digest()
        return f"{signing_input}.{_b64url_encode(sig)}"

    def validate_token(self, raw_token: str, now: float | None = None) -> TokenValidationResult:
        """Validate a JWT token locally."""
        if raw_token in self._revoked:
            return TokenValidationResult(TokenStatus.INVALID_SIGNATURE, reason="token revoked")

        parts = raw_token.split(".")
        if len(parts) != 3:
            return TokenValidationResult(TokenStatus.MALFORMED, reason="expected 3 parts")

        try:
            header = json.loads(_b64url_decode(parts[0]))
            payload = json.loads(_b64url_decode(parts[1]))
        except (json.JSONDecodeError, Exception):
            return TokenValidationResult(TokenStatus.MALFORMED, reason="invalid encoding")

        kid = header.get("kid", "")
        if kid not in self._keys:
            return TokenValidationResult(TokenStatus.UNKNOWN_KEY, reason=f"key {kid!r} not cached")

        # Verify signature
        signing_input = f"{parts[0]}.{parts[1]}"
        expected_sig = hmac.new(
            self._keys[kid], signing_input.encode(), hashlib.sha256,
        ).digest()
        try:
            actual_sig = _b64url_decode(parts[2])
        except Exception:
            return TokenValidationResult(TokenStatus.INVALID_SIGNATURE, reason="bad signature encoding")

        if not hmac.compare_digest(expected_sig, actual_sig):
            return TokenValidationResult(TokenStatus.INVALID_SIGNATURE, reason="signature mismatch")

        if now is None:
            now = time.time()
        exp = payload.get("exp", 0)
        iat = payload.get("iat", 0)

        token = OAuth8Token(
            subject=payload.get("sub", ""),
            issuer=payload.get("iss", ""),
            audience=payload.get("aud", ""),
            issued_at=iat,
            expires_at=exp,
            scopes=tuple(payload.get("scopes", ())),
            raw=raw_token,
        )

        if now >= exp:
            return TokenValidationResult(TokenStatus.EXPIRED, token=token, reason="token expired")

        return TokenValidationResult(TokenStatus.VALID, token=token)

    @property
    def key_count(self) -> int:
        return len(self._keys)


# ---------------------------------------------------------------------------
# ACL8
# ---------------------------------------------------------------------------

class ACL8Action(Enum):
    """ACL8 rule action."""

    PERMIT = auto()
    DENY = auto()


class ACL8Layer(Enum):
    """ACL8 enforcement layers (Section 1.4)."""

    NIC_FIRMWARE = auto()
    ZONE_SERVER_GATEWAY = auto()
    SWITCH_PORT_OAUTH2 = auto()


@dataclass(frozen=True, slots=True)
class ACL8Rule:
    """A single ACL8 access control rule."""

    source: str         # source identifier (address, zone, or "*")
    destination: str    # destination identifier (address, zone, or "*")
    action: ACL8Action = ACL8Action.DENY
    layer: ACL8Layer = ACL8Layer.ZONE_SERVER_GATEWAY
    description: str = ""


@dataclass(frozen=True, slots=True)
class ACL8Result:
    """Result of ACL8 evaluation."""

    action: ACL8Action
    matched_rule: ACL8Rule | None = None
    reason: str = ""

    @property
    def is_permitted(self) -> bool:
        return self.action == ACL8Action.PERMIT


class ACL8Engine:
    """ACL8 access control engine per Section 1.4.

    Enforces east-west security: devices communicate only with their
    designated service gateway.  Default deny — no lateral movement.
    """

    def __init__(self, default_action: ACL8Action = ACL8Action.DENY) -> None:
        self._rules: list[ACL8Rule] = []
        self._default_action = default_action

    def add_rule(self, rule: ACL8Rule) -> None:
        self._rules.append(rule)

    def remove_rule(self, index: int) -> ACL8Rule:
        return self._rules.pop(index)

    def evaluate(self, source: str, destination: str) -> ACL8Result:
        """Evaluate ACL8 rules for a source→destination pair.

        First match wins.  Default deny if no rule matches.
        """
        for rule in self._rules:
            src_match = rule.source == "*" or rule.source == source
            dst_match = rule.destination == "*" or rule.destination == destination
            if src_match and dst_match:
                return ACL8Result(
                    action=rule.action,
                    matched_rule=rule,
                    reason=rule.description or f"matched rule {rule.source}→{rule.destination}",
                )
        return ACL8Result(
            action=self._default_action,
            reason="default deny" if self._default_action == ACL8Action.DENY else "default permit",
        )

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def list_rules(self) -> list[ACL8Rule]:
        return list(self._rules)


# ---------------------------------------------------------------------------
# Zone Server service registry
# ---------------------------------------------------------------------------

class ZoneServiceType(Enum):
    """Services provided by a Zone Server."""

    DHCP8 = auto()
    DNS8 = auto()
    NTP8 = auto()
    NETLOG8 = auto()
    OAUTH8 = auto()
    WHOIS8 = auto()
    ACL8 = auto()
    XLATE8 = auto()


@dataclass(frozen=True, slots=True)
class ZoneService:
    """A service running on the Zone Server."""

    service_type: ZoneServiceType
    endpoint: str
    enabled: bool = True


class ZoneServerRole(Enum):
    """Zone Server role."""

    PRIMARY = auto()    # .254 — even VLANs
    SECONDARY = auto()  # .253 — odd VLANs


@dataclass
class ZoneServer:
    """Mock Zone Server per Section 1.3.

    Paired active/active platform that runs every service a network
    segment requires.  Primary (.254) is PVRST root for even VLANs,
    Secondary (.253) for odd VLANs.
    """

    role: ZoneServerRole
    zone_prefix: str = ""
    oauth8_cache: OAuth8Cache = field(default_factory=OAuth8Cache)
    acl8_engine: ACL8Engine = field(default_factory=ACL8Engine)
    _services: dict[ZoneServiceType, ZoneService] = field(default_factory=dict)

    @property
    def host_octet(self) -> int:
        return 254 if self.role == ZoneServerRole.PRIMARY else 253

    def register_service(self, service: ZoneService) -> None:
        self._services[service.service_type] = service

    def get_service(self, stype: ZoneServiceType) -> ZoneService | None:
        return self._services.get(stype)

    def list_services(self) -> list[ZoneService]:
        return list(self._services.values())

    @property
    def service_count(self) -> int:
        return len(self._services)

    def is_root_for_vlan(self, vlan_id: int) -> bool:
        """Check PVRST root eligibility per Section 17.4."""
        if self.role == ZoneServerRole.PRIMARY:
            return vlan_id % 2 == 0
        return vlan_id % 2 == 1

    def authenticate_device(self, token_raw: str, now: float | None = None) -> TokenValidationResult:
        """Authenticate a device via OAuth8 cache."""
        return self.oauth8_cache.validate_token(token_raw, now=now)

    def authorize_traffic(self, source: str, destination: str) -> ACL8Result:
        """Evaluate ACL8 for traffic authorization."""
        return self.acl8_engine.evaluate(source, destination)


def make_zone_server_pair(
    zone_prefix: str = "",
) -> tuple[ZoneServer, ZoneServer]:
    """Create a paired primary/secondary Zone Server."""
    primary = ZoneServer(role=ZoneServerRole.PRIMARY, zone_prefix=zone_prefix)
    secondary = ZoneServer(role=ZoneServerRole.SECONDARY, zone_prefix=zone_prefix)
    return primary, secondary
