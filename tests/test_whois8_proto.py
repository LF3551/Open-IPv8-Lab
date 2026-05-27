# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for standalone WHOIS8 protocol per draft-thain-whois8-00."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from ipv8lab.address import IPv8Address
from ipv8lab.whois8_proto import (
    WHOIS8ASNRecord,
    WHOIS8Client,
    WHOIS8Query,
    WHOIS8Response,
    WHOIS8Server,
    QueryType,
    ResponseCode,
    RIR,
    RouteRecord,
    sign_record,
    verify_signature,
)
from ipv8lab.cli.whois8_proto_cli import app

runner = CliRunner()


# ===================================================================
# WHOIS8ASNRecord
# ===================================================================

class TestWHOIS8ASNRecord:
    def test_prefix_str(self) -> None:
        r = WHOIS8ASNRecord(asn=64496, holder="Example-A")
        assert r.prefix_str == "0.0.251.240"

    def test_not_expired(self) -> None:
        r = WHOIS8ASNRecord(asn=64496, holder="X")
        assert not r.is_expired()

    def test_expired(self) -> None:
        r = WHOIS8ASNRecord(asn=64496, holder="X", expires_at=1.0)
        assert r.is_expired(now=100.0)

    def test_to_dict(self) -> None:
        r = WHOIS8ASNRecord(asn=64496, holder="X", rir=RIR.RIPE)
        d = r.to_dict()
        assert d["asn"] == 64496
        assert d["rir"] == "RIPE"


# ===================================================================
# Record signing
# ===================================================================

class TestRecordSigning:
    def test_sign_and_verify(self) -> None:
        r = WHOIS8ASNRecord(asn=64496, holder="Test", rir=RIR.ARIN)
        signed = sign_record(r, "secret123")
        assert signed.signature
        assert verify_signature(signed, "secret123")

    def test_wrong_secret(self) -> None:
        r = WHOIS8ASNRecord(asn=64496, holder="Test")
        signed = sign_record(r, "secret123")
        assert not verify_signature(signed, "wrong")

    def test_no_signature(self) -> None:
        r = WHOIS8ASNRecord(asn=64496, holder="Test")
        assert not verify_signature(r, "any")


# ===================================================================
# WHOIS8 Server — registration
# ===================================================================

class TestServerRegistration:
    def test_register_and_lookup(self) -> None:
        s = WHOIS8Server()
        s.register_asn(WHOIS8ASNRecord(asn=64496, holder="A"))
        assert 64496 in s.list_asns()

    def test_reserved_internal_zone(self) -> None:
        s = WHOIS8Server()
        with pytest.raises(ValueError, match="internal zone"):
            s.register_asn(WHOIS8ASNRecord(asn=2130706432, holder="X"))

    def test_reserved_rine(self) -> None:
        s = WHOIS8Server()
        with pytest.raises(ValueError, match="RINE"):
            s.register_asn(WHOIS8ASNRecord(asn=1677721600, holder="X"))

    def test_reserved_private_peering(self) -> None:
        s = WHOIS8Server()
        with pytest.raises(ValueError, match="65534"):
            s.register_asn(WHOIS8ASNRecord(asn=65534, holder="X"))

    def test_unregister(self) -> None:
        s = WHOIS8Server()
        s.register_asn(WHOIS8ASNRecord(asn=64496, holder="A"))
        s.unregister_asn(64496)
        assert 64496 not in s.list_asns()

    def test_unregister_not_found(self) -> None:
        s = WHOIS8Server()
        with pytest.raises(KeyError):
            s.unregister_asn(99999)

    def test_auto_signing(self) -> None:
        s = WHOIS8Server(signing_secret="key")
        s.register_asn(WHOIS8ASNRecord(asn=64496, holder="A"))
        rec = s._registry[64496]  # noqa: SLF001
        assert rec.signature
        assert verify_signature(rec, "key")


# ===================================================================
# Route registration
# ===================================================================

class TestRouteRegistration:
    def test_register_route(self) -> None:
        s = WHOIS8Server()
        s.register_asn(WHOIS8ASNRecord(asn=64496, holder="A"))
        s.register_route(RouteRecord(asn=64496, prefix_length=16))
        assert 64496 in s._routes  # noqa: SLF001

    def test_route_no_asn(self) -> None:
        s = WHOIS8Server()
        with pytest.raises(ValueError, match="not registered"):
            s.register_route(RouteRecord(asn=99999, prefix_length=16))

    def test_route_too_specific(self) -> None:
        s = WHOIS8Server()
        s.register_asn(WHOIS8ASNRecord(asn=64496, holder="A"))
        with pytest.raises(ValueError, match="exceeds"):
            s.register_route(RouteRecord(asn=64496, prefix_length=24))


# ===================================================================
# Server — query handling
# ===================================================================

class TestServerQueries:
    def _setup_server(self) -> WHOIS8Server:
        s = WHOIS8Server()
        s.register_asn(WHOIS8ASNRecord(asn=64496, holder="Example-A", anycast_v4="198.51.100.1"))
        s.register_asn(WHOIS8ASNRecord(asn=64497, holder="Example-B"))
        s.register_route(RouteRecord(asn=64496, prefix_length=16))
        return s

    def test_asn_lookup_ok(self) -> None:
        s = self._setup_server()
        r = s.handle_query(WHOIS8Query(query_type=QueryType.ASN_LOOKUP, asn=64496))
        assert r.code == ResponseCode.OK
        assert r.record is not None
        assert r.record.holder == "Example-A"

    def test_asn_lookup_not_found(self) -> None:
        s = self._setup_server()
        r = s.handle_query(WHOIS8Query(query_type=QueryType.ASN_LOOKUP, asn=99999))
        assert r.code == ResponseCode.NOT_FOUND

    def test_asn_lookup_reserved(self) -> None:
        s = self._setup_server()
        r = s.handle_query(WHOIS8Query(query_type=QueryType.ASN_LOOKUP, asn=65534))
        assert r.code == ResponseCode.RESERVED

    def test_route_validate_ok(self) -> None:
        s = self._setup_server()
        r = s.handle_query(WHOIS8Query(query_type=QueryType.ROUTE_VALIDATE, asn=64496, prefix_length=16))
        assert r.code == ResponseCode.OK
        assert r.route is not None

    def test_route_validate_too_specific(self) -> None:
        s = self._setup_server()
        r = s.handle_query(WHOIS8Query(query_type=QueryType.ROUTE_VALIDATE, asn=64496, prefix_length=24))
        assert r.code == ResponseCode.TOO_SPECIFIC

    def test_route_validate_not_found(self) -> None:
        s = self._setup_server()
        r = s.handle_query(WHOIS8Query(query_type=QueryType.ROUTE_VALIDATE, asn=99999, prefix_length=16))
        assert r.code == ResponseCode.NOT_FOUND

    def test_anycast_lookup_ok(self) -> None:
        s = self._setup_server()
        r = s.handle_query(WHOIS8Query(query_type=QueryType.ANYCAST_LOOKUP, asn=64496))
        assert r.code == ResponseCode.OK
        assert r.record is not None
        assert r.record.anycast_v4 == "198.51.100.1"

    def test_anycast_lookup_no_address(self) -> None:
        s = self._setup_server()
        r = s.handle_query(WHOIS8Query(query_type=QueryType.ANYCAST_LOOKUP, asn=64497))
        assert r.code == ResponseCode.NOT_FOUND
        assert "no anycast" in r.reason

    def test_bulk_query(self) -> None:
        s = self._setup_server()
        r = s.handle_query(WHOIS8Query(query_type=QueryType.BULK_QUERY, bulk_asns=(64496, 64497, 99999)))
        assert r.code == ResponseCode.OK
        assert len(r.bulk_records) == 2

    def test_record_verify_no_signing(self) -> None:
        s = self._setup_server()
        r = s.handle_query(WHOIS8Query(query_type=QueryType.RECORD_VERIFY, asn=64496))
        assert r.code == ResponseCode.OK
        assert "skipped" in r.reason

    def test_record_verify_with_signing(self) -> None:
        s = WHOIS8Server(signing_secret="key")
        s.register_asn(WHOIS8ASNRecord(asn=64496, holder="A"))
        r = s.handle_query(WHOIS8Query(query_type=QueryType.RECORD_VERIFY, asn=64496))
        assert r.code == ResponseCode.OK

    def test_query_count(self) -> None:
        s = self._setup_server()
        s.handle_query(WHOIS8Query(query_type=QueryType.ASN_LOOKUP, asn=64496))
        s.handle_query(WHOIS8Query(query_type=QueryType.ASN_LOOKUP, asn=64497))
        assert s.summary()["queries_served"] == 2


# ===================================================================
# WHOIS8 Client + cache
# ===================================================================

class TestClient:
    def _setup(self) -> WHOIS8Client:
        s = WHOIS8Server()
        s.register_asn(WHOIS8ASNRecord(asn=64496, holder="A", anycast_v4="10.0.0.1"))
        return WHOIS8Client(server=s)

    def test_lookup_miss_then_hit(self) -> None:
        c = self._setup()
        r1 = c.lookup(64496)
        assert r1.code == ResponseCode.OK
        r2 = c.lookup(64496)
        assert r2.code == ResponseCode.OK
        assert c._cache_hits == 1  # noqa: SLF001
        assert c._cache_misses == 1  # noqa: SLF001

    def test_validate_route(self) -> None:
        c = self._setup()
        r = c.validate_route(64496, 16)
        assert r.code == ResponseCode.OK

    def test_validate_destination_ipv4(self) -> None:
        c = self._setup()
        addr = IPv8Address.parse("0.0.0.0.10.0.0.1")
        r = c.validate_destination(addr)
        assert r.code == ResponseCode.OK
        assert "bypass" in (r.reason or "")

    def test_validate_destination_valid(self) -> None:
        c = self._setup()
        addr = IPv8Address.parse("64496-10.0.0.1")
        r = c.validate_destination(addr)
        assert r.code == ResponseCode.OK

    def test_anycast(self) -> None:
        c = self._setup()
        r = c.anycast_lookup(64496)
        assert r.code == ResponseCode.OK

    def test_flush_cache(self) -> None:
        c = self._setup()
        c.lookup(64496)
        n = c.flush_cache()
        assert n == 1
        assert c.summary()["cache_size"] == 0

    def test_summary(self) -> None:
        c = self._setup()
        d = c.summary()
        assert "cache_size" in d


# ===================================================================
# Response serialisation
# ===================================================================

class TestResponseSerialization:
    def test_response_to_dict(self) -> None:
        r = WHOIS8Response(code=ResponseCode.OK, query_type=QueryType.ASN_LOOKUP)
        d = r.to_dict()
        assert d["code"] == "OK"
        assert d["version"] == 1


# ===================================================================
# CLI tests
# ===================================================================

class TestWHOIS8ProtoCLI:
    def test_init_json(self) -> None:
        result = runner.invoke(app, ["init", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "registered_asns" in data

    def test_register_json(self) -> None:
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["register", "64496", "Example-A", "--country", "US", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["asn"] == 64496

    def test_register_reserved_error(self) -> None:
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["register", "65534", "X", "--json"])
        assert result.exit_code == 1

    def test_route_json(self) -> None:
        runner.invoke(app, ["init"])
        runner.invoke(app, ["register", "64496", "A"])
        result = runner.invoke(app, ["route", "64496", "16", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["prefix_length"] == 16

    def test_lookup_json(self) -> None:
        runner.invoke(app, ["init"])
        runner.invoke(app, ["register", "64496", "Example-A"])
        result = runner.invoke(app, ["lookup", "64496", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["code"] == "OK"

    def test_validate_json(self) -> None:
        runner.invoke(app, ["init"])
        runner.invoke(app, ["register", "64496", "A"])
        result = runner.invoke(app, ["validate", "64496", "16", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["code"] == "OK"

    def test_anycast_json(self) -> None:
        runner.invoke(app, ["init"])
        runner.invoke(app, ["register", "64496", "A", "--anycast", "198.51.100.1"])
        result = runner.invoke(app, ["anycast", "64496", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["code"] == "OK"

    def test_verify_json(self) -> None:
        runner.invoke(app, ["init", "--secret", "key"])
        runner.invoke(app, ["register", "64496", "A"])
        result = runner.invoke(app, ["verify", "64496", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["code"] == "OK"

    def test_list_json(self) -> None:
        runner.invoke(app, ["init"])
        runner.invoke(app, ["register", "64496", "A"])
        result = runner.invoke(app, ["list", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert 64496 in data["asns"]

    def test_cache_json(self) -> None:
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["cache", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "cache_size" in data

    def test_status_json(self) -> None:
        runner.invoke(app, ["init"])
        result = runner.invoke(app, ["status", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "queries_served" in data

    def test_no_args_help(self) -> None:
        result = runner.invoke(app, [])
        assert result.exit_code in (0, 2)
