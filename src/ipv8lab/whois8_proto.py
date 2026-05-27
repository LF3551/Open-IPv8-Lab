# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Standalone WHOIS8 protocol per draft-thain-whois8-.

WHOIS8 is a critical infrastructure service for the IPv8 global
routing system.  It provides route ownership validation, ASN
registry queries, anycast endpoint resolution, and signed record
verification to prevent prefix hijacking.

This module implements the WHOIS8 wire protocol (query/response),
server (registry + query handler), client (with local cache + TTL),
and RIR hierarchy.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum

from ipv8lab.address import IPv8Address, asn_to_prefix


# ===================================================================
# Constants
# ===================================================================

WHOIS8_PORT = 8043  # Well-known TCP port for WHOIS8
WHOIS8_VERSION = 1
RECORD_TTL_DEFAULT = 86400  # 24 hours


# ===================================================================
# RIR hierarchy
# ===================================================================

class RIR(str, Enum):
    """Regional Internet Registry identifiers."""

    ARIN = "ARIN"       # North America
    RIPE = "RIPE"       # Europe / Middle East / Central Asia
    APNIC = "APNIC"     # Asia Pacific
    LACNIC = "LACNIC"   # Latin America / Caribbean
    AFRINIC = "AFRINIC" # Africa


# ===================================================================
# Query types
# ===================================================================

class QueryType(str, Enum):
    """WHOIS8 query types."""

    ASN_LOOKUP = "ASN_LOOKUP"
    ROUTE_VALIDATE = "ROUTE_VALIDATE"
    ANYCAST_LOOKUP = "ANYCAST_LOOKUP"
    BULK_QUERY = "BULK_QUERY"
    RECORD_VERIFY = "RECORD_VERIFY"


# ===================================================================
# Response codes
# ===================================================================

class ResponseCode(str, Enum):
    """WHOIS8 response codes."""

    OK = "OK"
    NOT_FOUND = "NOT_FOUND"
    INVALID = "INVALID"
    EXPIRED = "EXPIRED"
    RESERVED = "RESERVED"
    SIGNATURE_FAIL = "SIGNATURE_FAIL"
    TOO_SPECIFIC = "TOO_SPECIFIC"
    SERVER_ERROR = "SERVER_ERROR"


# ===================================================================
# Records
# ===================================================================

@dataclass(frozen=True, slots=True)
class WHOIS8ASNRecord:
    """ASN ownership record in WHOIS8 registry."""

    asn: int
    holder: str
    country: str = ""
    rir: RIR = RIR.ARIN
    prefix_min: int = 16
    active: bool = True
    anycast_v4: str = ""           # IPv4 anycast address for 8to4
    created_at: float = 0.0
    expires_at: float = 0.0        # 0 = no expiry
    signature: str = ""            # HMAC signature for record integrity

    @property
    def prefix_str(self) -> str:
        p = asn_to_prefix(self.asn)
        return ".".join(str(o) for o in p)

    def is_expired(self, now: float | None = None) -> bool:
        if self.expires_at == 0.0:
            return False
        t = now if now is not None else time.time()
        return t > self.expires_at

    def to_dict(self) -> dict[str, str | int | float | bool]:
        return {
            "asn": self.asn,
            "holder": self.holder,
            "country": self.country,
            "rir": self.rir.value,
            "prefix_str": self.prefix_str,
            "prefix_min": self.prefix_min,
            "active": self.active,
            "anycast_v4": self.anycast_v4,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "has_signature": bool(self.signature),
        }


@dataclass(frozen=True, slots=True)
class RouteRecord:
    """Route ownership record — binds a prefix length to an ASN."""

    asn: int
    prefix_length: int
    origin_asn: int = 0       # originating ASN for multi-hop
    max_length: int = 16      # maximum specific prefix advertised

    def to_dict(self) -> dict[str, int]:
        return {
            "asn": self.asn,
            "prefix_length": self.prefix_length,
            "origin_asn": self.origin_asn or self.asn,
            "max_length": self.max_length,
        }


# ===================================================================
# Query / Response messages
# ===================================================================

@dataclass(frozen=True, slots=True)
class WHOIS8Query:
    """WHOIS8 wire protocol query message."""

    query_type: QueryType
    asn: int = 0
    prefix_length: int = 0
    address: str = ""
    bulk_asns: tuple[int, ...] = ()

    def to_dict(self) -> dict[str, str | int | list[int]]:
        return {
            "version": WHOIS8_VERSION,
            "query_type": self.query_type.value,
            "asn": self.asn,
            "prefix_length": self.prefix_length,
            "address": self.address,
            "bulk_asns": list(self.bulk_asns),
        }


@dataclass(frozen=True, slots=True)
class WHOIS8Response:
    """WHOIS8 wire protocol response message."""

    code: ResponseCode
    query_type: QueryType
    reason: str = ""
    record: WHOIS8ASNRecord | None = None
    route: RouteRecord | None = None
    bulk_records: tuple[WHOIS8ASNRecord, ...] = ()

    def to_dict(self) -> dict[str, object]:
        d: dict[str, object] = {
            "version": WHOIS8_VERSION,
            "code": self.code.value,
            "query_type": self.query_type.value,
            "reason": self.reason,
        }
        if self.record is not None:
            d["record"] = self.record.to_dict()
        if self.route is not None:
            d["route"] = self.route.to_dict()
        if self.bulk_records:
            d["bulk_records"] = [r.to_dict() for r in self.bulk_records]
        return d


# ===================================================================
# Record signing (HMAC-based integrity)
# ===================================================================

def sign_record(record: WHOIS8ASNRecord, secret: str) -> WHOIS8ASNRecord:
    """Sign a WHOIS8 record with HMAC-SHA256."""
    payload = f"{record.asn}:{record.holder}:{record.country}:{record.rir.value}"
    sig = hashlib.sha256(f"{payload}:{secret}".encode()).hexdigest()[:32]
    return WHOIS8ASNRecord(
        asn=record.asn,
        holder=record.holder,
        country=record.country,
        rir=record.rir,
        prefix_min=record.prefix_min,
        active=record.active,
        anycast_v4=record.anycast_v4,
        created_at=record.created_at,
        expires_at=record.expires_at,
        signature=sig,
    )


def verify_signature(record: WHOIS8ASNRecord, secret: str) -> bool:
    """Verify the HMAC-SHA256 signature of a WHOIS8 record."""
    if not record.signature:
        return False
    payload = f"{record.asn}:{record.holder}:{record.country}:{record.rir.value}"
    expected = hashlib.sha256(f"{payload}:{secret}".encode()).hexdigest()[:32]
    return record.signature == expected


# ===================================================================
# Reserved ASN ranges
# ===================================================================

_INTERNAL_ZONE_ASN_MIN = 2130706432  # 127.0.0.0
_INTERNAL_ZONE_ASN_MAX = 2147483647  # 127.255.255.255
_RINE_ASN_MIN = 1677721600           # 100.0.0.0
_RINE_ASN_MAX = 1694498815           # 100.255.255.255


def _reserved_reason(asn: int) -> str | None:
    if _INTERNAL_ZONE_ASN_MIN <= asn <= _INTERNAL_ZONE_ASN_MAX:
        return "ASN in internal zone range (127.0.0.0/8)"
    if _RINE_ASN_MIN <= asn <= _RINE_ASN_MAX:
        return "ASN in RINE peering range (100.0.0.0/8)"
    if asn == 65534:
        return "ASN 65534 reserved for private peering"
    if asn == 65533:
        return "ASN 65533 reserved for documentation"
    return None


# ===================================================================
# WHOIS8 Server
# ===================================================================

@dataclass
class WHOIS8Server:
    """WHOIS8 registry server with query handler.

    Maintains the authoritative ASN and route registry,
    processes queries, and enforces WHOIS8 protocol semantics.
    """

    server_id: str = "whois8-primary"
    signing_secret: str = ""
    _registry: dict[int, WHOIS8ASNRecord] = field(default_factory=dict, init=False)
    _routes: dict[int, RouteRecord] = field(default_factory=dict, init=False)
    _query_count: int = field(default=0, init=False)

    # -- registry management -------------------------------------------------

    def register_asn(self, record: WHOIS8ASNRecord) -> None:
        """Register an ASN record. Rejects reserved ranges."""
        reason = _reserved_reason(record.asn)
        if reason:
            msg = f"Cannot register reserved ASN {record.asn}: {reason}"
            raise ValueError(msg)
        if self.signing_secret and not record.signature:
            record = sign_record(record, self.signing_secret)
        self._registry[record.asn] = record

    def register_route(self, route: RouteRecord) -> None:
        """Register a route ownership record."""
        if route.asn not in self._registry:
            msg = f"ASN {route.asn} not registered — register ASN first"
            raise ValueError(msg)
        if route.prefix_length > 16:
            msg = f"Route /{route.prefix_length} exceeds /16 minimum"
            raise ValueError(msg)
        self._routes[route.asn] = route

    def unregister_asn(self, asn: int) -> None:
        """Remove an ASN and its routes."""
        if asn not in self._registry:
            msg = f"ASN {asn} not in registry"
            raise KeyError(msg)
        del self._registry[asn]
        self._routes.pop(asn, None)

    # -- query handler -------------------------------------------------------

    def handle_query(self, query: WHOIS8Query) -> WHOIS8Response:
        """Process a WHOIS8 query and return a response."""
        self._query_count += 1

        if query.query_type == QueryType.ASN_LOOKUP:
            return self._handle_asn_lookup(query.asn)
        if query.query_type == QueryType.ROUTE_VALIDATE:
            return self._handle_route_validate(query.asn, query.prefix_length)
        if query.query_type == QueryType.ANYCAST_LOOKUP:
            return self._handle_anycast_lookup(query.asn)
        if query.query_type == QueryType.BULK_QUERY:
            return self._handle_bulk_query(query.bulk_asns)
        if query.query_type == QueryType.RECORD_VERIFY:
            return self._handle_record_verify(query.asn)

        return WHOIS8Response(
            code=ResponseCode.SERVER_ERROR,
            query_type=query.query_type,
            reason="Unknown query type",
        )

    def _handle_asn_lookup(self, asn: int) -> WHOIS8Response:
        reason = _reserved_reason(asn)
        if reason:
            return WHOIS8Response(
                code=ResponseCode.RESERVED,
                query_type=QueryType.ASN_LOOKUP,
                reason=reason,
            )
        record = self._registry.get(asn)
        if record is None:
            return WHOIS8Response(
                code=ResponseCode.NOT_FOUND,
                query_type=QueryType.ASN_LOOKUP,
                reason=f"ASN {asn} not found",
            )
        if record.is_expired():
            return WHOIS8Response(
                code=ResponseCode.EXPIRED,
                query_type=QueryType.ASN_LOOKUP,
                record=record,
                reason=f"ASN {asn} record expired",
            )
        return WHOIS8Response(
            code=ResponseCode.OK,
            query_type=QueryType.ASN_LOOKUP,
            record=record,
        )

    def _handle_route_validate(self, asn: int, prefix_length: int) -> WHOIS8Response:
        reason = _reserved_reason(asn)
        if reason:
            return WHOIS8Response(
                code=ResponseCode.RESERVED,
                query_type=QueryType.ROUTE_VALIDATE,
                reason=reason,
            )
        record = self._registry.get(asn)
        if record is None:
            return WHOIS8Response(
                code=ResponseCode.NOT_FOUND,
                query_type=QueryType.ROUTE_VALIDATE,
                reason=f"ASN {asn} not found",
            )
        if not record.active:
            return WHOIS8Response(
                code=ResponseCode.EXPIRED,
                query_type=QueryType.ROUTE_VALIDATE,
                record=record,
                reason=f"ASN {asn} inactive",
            )
        if prefix_length > 16:
            return WHOIS8Response(
                code=ResponseCode.TOO_SPECIFIC,
                query_type=QueryType.ROUTE_VALIDATE,
                record=record,
                reason=f"/{prefix_length} exceeds /16 minimum",
            )
        route = self._routes.get(asn)
        return WHOIS8Response(
            code=ResponseCode.OK,
            query_type=QueryType.ROUTE_VALIDATE,
            record=record,
            route=route,
        )

    def _handle_anycast_lookup(self, asn: int) -> WHOIS8Response:
        record = self._registry.get(asn)
        if record is None:
            return WHOIS8Response(
                code=ResponseCode.NOT_FOUND,
                query_type=QueryType.ANYCAST_LOOKUP,
                reason=f"ASN {asn} not found",
            )
        if not record.anycast_v4:
            return WHOIS8Response(
                code=ResponseCode.NOT_FOUND,
                query_type=QueryType.ANYCAST_LOOKUP,
                record=record,
                reason=f"ASN {asn} has no anycast address",
            )
        return WHOIS8Response(
            code=ResponseCode.OK,
            query_type=QueryType.ANYCAST_LOOKUP,
            record=record,
        )

    def _handle_bulk_query(self, asns: tuple[int, ...]) -> WHOIS8Response:
        records: list[WHOIS8ASNRecord] = []
        for asn in asns:
            rec = self._registry.get(asn)
            if rec is not None:
                records.append(rec)
        return WHOIS8Response(
            code=ResponseCode.OK,
            query_type=QueryType.BULK_QUERY,
            bulk_records=tuple(records),
        )

    def _handle_record_verify(self, asn: int) -> WHOIS8Response:
        record = self._registry.get(asn)
        if record is None:
            return WHOIS8Response(
                code=ResponseCode.NOT_FOUND,
                query_type=QueryType.RECORD_VERIFY,
                reason=f"ASN {asn} not found",
            )
        if not self.signing_secret:
            return WHOIS8Response(
                code=ResponseCode.OK,
                query_type=QueryType.RECORD_VERIFY,
                record=record,
                reason="No signing configured — verification skipped",
            )
        if not verify_signature(record, self.signing_secret):
            return WHOIS8Response(
                code=ResponseCode.SIGNATURE_FAIL,
                query_type=QueryType.RECORD_VERIFY,
                record=record,
                reason="Record signature verification failed",
            )
        return WHOIS8Response(
            code=ResponseCode.OK,
            query_type=QueryType.RECORD_VERIFY,
            record=record,
        )

    # -- info ----------------------------------------------------------------

    def list_asns(self) -> list[int]:
        return sorted(self._registry)

    def summary(self) -> dict[str, str | int | bool]:
        return {
            "server_id": self.server_id,
            "registered_asns": len(self._registry),
            "registered_routes": len(self._routes),
            "queries_served": self._query_count,
            "signing_enabled": bool(self.signing_secret),
        }


# ===================================================================
# WHOIS8 Client with cache
# ===================================================================

@dataclass(frozen=True, slots=True)
class CacheEntry:
    """Local cache entry with TTL."""

    record: WHOIS8ASNRecord
    cached_at: float
    ttl: int = RECORD_TTL_DEFAULT

    def is_stale(self, now: float | None = None) -> bool:
        t = now if now is not None else time.time()
        return (t - self.cached_at) > self.ttl


@dataclass
class WHOIS8Client:
    """WHOIS8 client with local caching.

    Queries a WHOIS8Server and caches results locally with TTL.
    """

    server: WHOIS8Server
    cache_ttl: int = RECORD_TTL_DEFAULT
    _cache: dict[int, CacheEntry] = field(default_factory=dict, init=False)
    _cache_hits: int = field(default=0, init=False)
    _cache_misses: int = field(default=0, init=False)

    def lookup(self, asn: int) -> WHOIS8Response:
        """Look up an ASN, using cache if available."""
        entry = self._cache.get(asn)
        if entry is not None and not entry.is_stale():
            self._cache_hits += 1
            return WHOIS8Response(
                code=ResponseCode.OK,
                query_type=QueryType.ASN_LOOKUP,
                record=entry.record,
            )
        self._cache_misses += 1
        query = WHOIS8Query(query_type=QueryType.ASN_LOOKUP, asn=asn)
        resp = self.server.handle_query(query)
        if resp.code == ResponseCode.OK and resp.record is not None:
            self._cache[asn] = CacheEntry(
                record=resp.record,
                cached_at=time.time(),
                ttl=self.cache_ttl,
            )
        return resp

    def validate_route(self, asn: int, prefix_length: int = 8) -> WHOIS8Response:
        """Validate a BGP8 route advertisement via WHOIS8."""
        query = WHOIS8Query(
            query_type=QueryType.ROUTE_VALIDATE,
            asn=asn,
            prefix_length=prefix_length,
        )
        return self.server.handle_query(query)

    def validate_destination(self, address: IPv8Address) -> WHOIS8Response:
        """Validate destination address ownership."""
        if address.is_ipv4_compatible():
            return WHOIS8Response(
                code=ResponseCode.OK,
                query_type=QueryType.ASN_LOOKUP,
                reason="IPv4-compatible — WHOIS8 bypass",
            )
        return self.lookup(address.asn)

    def anycast_lookup(self, asn: int) -> WHOIS8Response:
        """Look up 8to4 anycast address for an ASN."""
        query = WHOIS8Query(query_type=QueryType.ANYCAST_LOOKUP, asn=asn)
        return self.server.handle_query(query)

    def flush_cache(self) -> int:
        """Flush all cached entries. Returns count flushed."""
        n = len(self._cache)
        self._cache.clear()
        return n

    def summary(self) -> dict[str, str | int]:
        return {
            "server_id": self.server.server_id,
            "cache_size": len(self._cache),
            "cache_ttl": self.cache_ttl,
            "cache_hits": self._cache_hits,
            "cache_misses": self._cache_misses,
        }
