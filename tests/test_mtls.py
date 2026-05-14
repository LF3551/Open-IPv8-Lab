# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Tests for mTLS / encryption layer."""

from __future__ import annotations

import hashlib
import hmac
import json

import pytest

from ipv8lab.mtls import (
    AlertDescription,
    CertificateAuthority,
    CertificateType,
    CertificateVerify,
    ClientHello,
    EncryptedMessage,
    KeyPair,
    MTLSSession,
    TLSAlert,
    client_handshake,
    issue_client_certificate,
    make_mtls_zone_setup,
    perform_mtls_handshake,
)


NOW = 1_700_000_000.0


# ---------------------------------------------------------------------------
# KeyPair
# ---------------------------------------------------------------------------


class TestKeyPair:
    def test_generate(self) -> None:
        kp = KeyPair.generate()
        assert len(kp.private_key) == 32
        assert len(kp.public_key) == 32
        assert kp.private_key != kp.public_key

    def test_from_seed_deterministic(self) -> None:
        kp1 = KeyPair.from_seed(b"test-seed")
        kp2 = KeyPair.from_seed(b"test-seed")
        assert kp1.private_key == kp2.private_key
        assert kp1.public_key == kp2.public_key

    def test_from_seed_different_seeds(self) -> None:
        kp1 = KeyPair.from_seed(b"seed-a")
        kp2 = KeyPair.from_seed(b"seed-b")
        assert kp1.private_key != kp2.private_key

    def test_sign_verify(self) -> None:
        kp = KeyPair.from_seed(b"sign-test")
        data = b"hello world"
        sig = kp.sign(data)
        assert kp.verify(data, sig)

    def test_sign_verify_wrong_data(self) -> None:
        kp = KeyPair.from_seed(b"sign-test")
        sig = kp.sign(b"hello")
        assert not kp.verify(b"world", sig)

    def test_sign_verify_wrong_sig(self) -> None:
        kp = KeyPair.from_seed(b"sign-test")
        sig = kp.sign(b"hello")
        assert not kp.verify(b"hello", b"wrong" + sig[5:])


# ---------------------------------------------------------------------------
# Certificate Authority
# ---------------------------------------------------------------------------


class TestCertificateAuthority:
    def test_init(self) -> None:
        ca = CertificateAuthority(name="Test-CA", now=NOW, seed=b"test")
        assert ca.name == "Test-CA"
        assert ca.issued_count == 1  # self-signed CA cert

    def test_ca_certificate(self) -> None:
        ca = CertificateAuthority(name="Test-CA", now=NOW, seed=b"test")
        cert = ca.ca_certificate
        assert cert.subject == "Test-CA"
        assert cert.issuer == "Test-CA"
        assert cert.cert_type == CertificateType.CA
        assert cert.is_valid_at(NOW)

    def test_issue_server_cert(self) -> None:
        ca = CertificateAuthority(name="Test-CA", now=NOW, seed=b"test")
        kp = KeyPair.from_seed(b"server")
        cert = ca.issue_certificate(
            subject="zone-primary",
            cert_type=CertificateType.SERVER,
            public_key=kp.public_key,
            now=NOW,
        )
        assert cert.subject == "zone-primary"
        assert cert.issuer == "Test-CA"
        assert cert.cert_type == CertificateType.SERVER
        assert cert.serial_number == 2

    def test_issue_client_cert(self) -> None:
        ca = CertificateAuthority(name="Test-CA", now=NOW, seed=b"test")
        kp = KeyPair.from_seed(b"client")
        cert = ca.issue_certificate(
            subject="device-1",
            cert_type=CertificateType.CLIENT,
            public_key=kp.public_key,
            now=NOW,
        )
        assert cert.subject == "device-1"
        assert cert.cert_type == CertificateType.CLIENT

    def test_verify_valid_cert(self) -> None:
        ca = CertificateAuthority(name="Test-CA", now=NOW, seed=b"test")
        kp = KeyPair.from_seed(b"dev")
        cert = ca.issue_certificate("dev", CertificateType.CLIENT, kp.public_key, now=NOW)
        result = ca.verify_certificate(cert, now=NOW)
        assert result.valid

    def test_verify_expired_cert(self) -> None:
        ca = CertificateAuthority(name="Test-CA", now=NOW, seed=b"test")
        kp = KeyPair.from_seed(b"dev")
        cert = ca.issue_certificate(
            "dev", CertificateType.CLIENT, kp.public_key, validity_days=1, now=NOW,
        )
        result = ca.verify_certificate(cert, now=NOW + 200_000)
        assert not result.valid
        assert "expired" in result.reason

    def test_verify_revoked_cert(self) -> None:
        ca = CertificateAuthority(name="Test-CA", now=NOW, seed=b"test")
        kp = KeyPair.from_seed(b"dev")
        cert = ca.issue_certificate("dev", CertificateType.CLIENT, kp.public_key, now=NOW)
        ca.revoke_certificate(cert.serial_number)
        result = ca.verify_certificate(cert, now=NOW)
        assert not result.valid
        assert "revoked" in result.reason

    def test_verify_wrong_issuer(self) -> None:
        ca = CertificateAuthority(name="Test-CA", now=NOW, seed=b"test")
        from ipv8lab.mtls import Certificate

        fake = Certificate(
            serial_number=999,
            subject="fake",
            issuer="Other-CA",
            cert_type=CertificateType.CLIENT,
            public_key=b"\x00" * 32,
            not_before=NOW,
            not_after=NOW + 86400,
            signature=b"\x00" * 32,
        )
        result = ca.verify_certificate(fake, now=NOW)
        assert not result.valid
        assert "unknown issuer" in result.reason

    def test_verify_bad_signature(self) -> None:
        ca = CertificateAuthority(name="Test-CA", now=NOW, seed=b"test")
        kp = KeyPair.from_seed(b"dev")
        cert = ca.issue_certificate("dev", CertificateType.CLIENT, kp.public_key, now=NOW)
        from ipv8lab.mtls import Certificate

        tampered = Certificate(
            serial_number=cert.serial_number,
            subject=cert.subject,
            issuer=cert.issuer,
            cert_type=cert.cert_type,
            public_key=cert.public_key,
            not_before=cert.not_before,
            not_after=cert.not_after,
            signature=b"\xff" * 32,
        )
        result = ca.verify_certificate(tampered, now=NOW)
        assert not result.valid
        assert "invalid signature" in result.reason

    def test_revoke_nonexistent(self) -> None:
        ca = CertificateAuthority(name="Test-CA", now=NOW, seed=b"test")
        assert not ca.revoke_certificate(999)

    def test_is_revoked(self) -> None:
        ca = CertificateAuthority(name="Test-CA", now=NOW, seed=b"test")
        kp = KeyPair.from_seed(b"dev")
        cert = ca.issue_certificate("dev", CertificateType.CLIENT, kp.public_key, now=NOW)
        assert not ca.is_revoked(cert.serial_number)
        ca.revoke_certificate(cert.serial_number)
        assert ca.is_revoked(cert.serial_number)

    def test_get_certificate(self) -> None:
        ca = CertificateAuthority(name="Test-CA", now=NOW, seed=b"test")
        kp = KeyPair.from_seed(b"dev")
        cert = ca.issue_certificate("dev", CertificateType.CLIENT, kp.public_key, now=NOW)
        assert ca.get_certificate(cert.serial_number) == cert
        assert ca.get_certificate(999) is None

    def test_serial_increments(self) -> None:
        ca = CertificateAuthority(name="Test-CA", now=NOW, seed=b"test")
        kp = KeyPair.from_seed(b"a")
        c1 = ca.issue_certificate("a", CertificateType.CLIENT, kp.public_key, now=NOW)
        c2 = ca.issue_certificate("b", CertificateType.CLIENT, kp.public_key, now=NOW)
        assert c2.serial_number == c1.serial_number + 1


# ---------------------------------------------------------------------------
# Certificate
# ---------------------------------------------------------------------------


class TestCertificate:
    def test_is_expired(self) -> None:
        ca = CertificateAuthority(name="CA", now=NOW, seed=b"c")
        kp = KeyPair.from_seed(b"x")
        cert = ca.issue_certificate("x", CertificateType.CLIENT, kp.public_key, validity_days=1, now=NOW)
        assert not cert.is_expired(NOW)
        assert cert.is_expired(NOW + 100_000)

    def test_is_not_yet_valid(self) -> None:
        ca = CertificateAuthority(name="CA", now=NOW, seed=b"c")
        kp = KeyPair.from_seed(b"x")
        cert = ca.issue_certificate("x", CertificateType.CLIENT, kp.public_key, now=NOW)
        assert cert.is_not_yet_valid(NOW - 1)
        assert not cert.is_not_yet_valid(NOW)

    def test_fingerprint_deterministic(self) -> None:
        ca = CertificateAuthority(name="CA", now=NOW, seed=b"c")
        kp = KeyPair.from_seed(b"x")
        cert = ca.issue_certificate("x", CertificateType.CLIENT, kp.public_key, now=NOW)
        assert cert.fingerprint() == cert.fingerprint()
        assert len(cert.fingerprint()) == 64  # sha256 hex

    def test_to_dict(self) -> None:
        ca = CertificateAuthority(name="CA", now=NOW, seed=b"c")
        kp = KeyPair.from_seed(b"x")
        cert = ca.issue_certificate("x", CertificateType.CLIENT, kp.public_key, now=NOW)
        d = cert.to_dict()
        assert d["subject"] == "x"
        assert d["type"] == "CLIENT"
        assert "fingerprint" in d


# ---------------------------------------------------------------------------
# mTLS Handshake
# ---------------------------------------------------------------------------


class TestMTLSHandshake:
    @pytest.fixture(autouse=True)
    def setup(self) -> None:
        self.ca = CertificateAuthority(name="Test-CA", now=NOW, seed=b"hs")
        self.server_key = KeyPair.from_seed(b"server")
        self.server_cert = self.ca.issue_certificate(
            "zone-primary", CertificateType.SERVER, self.server_key.public_key, now=NOW,
        )
        self.client_key = KeyPair.from_seed(b"client")
        self.client_cert = self.ca.issue_certificate(
            "device-1", CertificateType.CLIENT, self.client_key.public_key, now=NOW,
        )

    def test_full_handshake_success(self) -> None:
        result = perform_mtls_handshake(
            ca=self.ca,
            server_cert=self.server_cert,
            server_key=self.server_key,
            client_cert=self.client_cert,
            client_key=self.client_key,
            now=NOW,
        )
        assert result.established
        assert result.client_subject == "device-1"
        assert result.server_subject == "zone-primary"
        assert result.cipher == "TLS_AES_256_GCM_SHA384"
        assert len(result.session_key) == 32

    def test_handshake_expired_server_cert(self) -> None:
        expired_cert = self.ca.issue_certificate(
            "expired-server", CertificateType.SERVER, self.server_key.public_key,
            validity_days=1, now=NOW - 200_000,
        )
        result = perform_mtls_handshake(
            ca=self.ca,
            server_cert=expired_cert,
            server_key=self.server_key,
            client_cert=self.client_cert,
            client_key=self.client_key,
            now=NOW,
        )
        assert not result.established
        assert result.alert is not None
        assert result.alert.description == AlertDescription.CERTIFICATE_EXPIRED

    def test_handshake_expired_client_cert(self) -> None:
        expired_client = self.ca.issue_certificate(
            "expired-device", CertificateType.CLIENT, self.client_key.public_key,
            validity_days=1, now=NOW - 200_000,
        )
        result = perform_mtls_handshake(
            ca=self.ca,
            server_cert=self.server_cert,
            server_key=self.server_key,
            client_cert=expired_client,
            client_key=self.client_key,
            now=NOW,
        )
        assert not result.established
        assert result.alert is not None
        assert result.alert.description == AlertDescription.CERTIFICATE_EXPIRED

    def test_handshake_revoked_client_cert(self) -> None:
        self.ca.revoke_certificate(self.client_cert.serial_number)
        result = perform_mtls_handshake(
            ca=self.ca,
            server_cert=self.server_cert,
            server_key=self.server_key,
            client_cert=self.client_cert,
            client_key=self.client_key,
            now=NOW,
        )
        assert not result.established
        assert result.alert is not None
        assert result.alert.description == AlertDescription.CERTIFICATE_REVOKED

    def test_handshake_wrong_cert_type(self) -> None:
        # Client sends SERVER cert as client cert
        wrong_type = self.ca.issue_certificate(
            "wrong", CertificateType.SERVER, self.client_key.public_key, now=NOW,
        )
        result = perform_mtls_handshake(
            ca=self.ca,
            server_cert=self.server_cert,
            server_key=self.server_key,
            client_cert=wrong_type,
            client_key=self.client_key,
            now=NOW,
        )
        assert not result.established
        assert result.alert is not None
        assert result.alert.description == AlertDescription.BAD_CERTIFICATE

    def test_client_hello_to_wrong_state(self) -> None:
        session = MTLSSession(ca=self.ca, server_cert=self.server_cert, server_key=self.server_key)
        hello = ClientHello(client_random=b"\x00" * 32)
        session.process_client_hello(hello)
        # Send another ClientHello — should fail
        result = session.process_client_hello(hello)
        assert isinstance(result, TLSAlert)
        assert result.description == AlertDescription.HANDSHAKE_FAILURE

    def test_cert_verify_to_wrong_state(self) -> None:
        session = MTLSSession(ca=self.ca, server_cert=self.server_cert, server_key=self.server_key)
        cv = CertificateVerify(client_certificate=self.client_cert, signature=b"\x00" * 32)
        result = session.process_certificate_verify(cv, now=NOW)
        assert isinstance(result, TLSAlert)
        assert result.description == AlertDescription.HANDSHAKE_FAILURE


# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------


class TestEncryption:
    @pytest.fixture(autouse=True)
    def setup(self) -> None:
        self.ca = CertificateAuthority(name="Enc-CA", now=NOW, seed=b"enc")
        self.server_key = KeyPair.from_seed(b"enc-server")
        self.server_cert = self.ca.issue_certificate(
            "enc-zone", CertificateType.SERVER, self.server_key.public_key, now=NOW,
        )
        self.client_key = KeyPair.from_seed(b"enc-client")
        self.client_cert = self.ca.issue_certificate(
            "enc-device", CertificateType.CLIENT, self.client_key.public_key, now=NOW,
        )
        # Establish session
        self.session = MTLSSession(
            ca=self.ca, server_cert=self.server_cert, server_key=self.server_key,
        )
        client_random = b"\x42" * 32
        hello = ClientHello(client_random=client_random)
        server_hello = self.session.process_client_hello(hello)
        assert not isinstance(server_hello, TLSAlert)
        transcript_hash = hashlib.sha256(
            client_random + server_hello.server_random,
        ).digest()
        signature = hmac.new(
            self.client_cert.public_key, transcript_hash, hashlib.sha256,
        ).digest()
        cv = CertificateVerify(client_certificate=self.client_cert, signature=signature)
        finished = self.session.process_certificate_verify(cv, now=NOW)
        assert not isinstance(finished, TLSAlert)

    def test_encrypt_decrypt_roundtrip(self) -> None:
        plaintext = b"hello zone server"
        encrypted = self.session.encrypt(plaintext)
        decrypted = self.session.decrypt(encrypted)
        assert decrypted == plaintext

    def test_encrypt_different_nonces(self) -> None:
        enc1 = self.session.encrypt(b"a")
        enc2 = self.session.encrypt(b"a")
        assert enc1.nonce != enc2.nonce

    def test_decrypt_tampered_ciphertext(self) -> None:
        encrypted = self.session.encrypt(b"secret")
        tampered = EncryptedMessage(
            nonce=encrypted.nonce,
            ciphertext=b"\xff" * len(encrypted.ciphertext),
            mac=encrypted.mac,
        )
        assert self.session.decrypt(tampered) is None

    def test_decrypt_tampered_mac(self) -> None:
        encrypted = self.session.encrypt(b"secret")
        tampered = EncryptedMessage(
            nonce=encrypted.nonce,
            ciphertext=encrypted.ciphertext,
            mac=b"\x00" * 32,
        )
        assert self.session.decrypt(tampered) is None

    def test_encrypt_before_established(self) -> None:
        session = MTLSSession(
            ca=self.ca, server_cert=self.server_cert, server_key=self.server_key,
        )
        with pytest.raises(RuntimeError, match="not established"):
            session.encrypt(b"test")

    def test_decrypt_before_established(self) -> None:
        session = MTLSSession(
            ca=self.ca, server_cert=self.server_cert, server_key=self.server_key,
        )
        msg = EncryptedMessage(nonce=b"\x00" * 12, ciphertext=b"x", mac=b"\x00" * 32)
        with pytest.raises(RuntimeError, match="not established"):
            session.decrypt(msg)


# ---------------------------------------------------------------------------
# ZoneServerMTLS
# ---------------------------------------------------------------------------


class TestZoneServerMTLS:
    @pytest.fixture(autouse=True)
    def setup(self) -> None:
        self.ca, self.mtls_server, self.server_cert, self.server_key = make_mtls_zone_setup(
            zone_name="test-zone", ca_name="ZS-CA", now=NOW, seed=b"zs",
        )
        self.client_cert, self.client_key = issue_client_certificate(
            self.ca, "device-alpha", now=NOW,
        )

    def test_start_handshake(self) -> None:
        hello = ClientHello(client_random=b"\x01" * 32)
        session_id, result = self.mtls_server.start_handshake(hello)
        assert isinstance(result, type(result))  # ServerHello
        assert not isinstance(result, TLSAlert)
        assert session_id

    def test_complete_handshake(self) -> None:
        client_random = b"\x01" * 32
        hello = ClientHello(client_random=client_random)
        session_id, server_hello = self.mtls_server.start_handshake(hello)
        assert not isinstance(server_hello, TLSAlert)

        transcript_hash = hashlib.sha256(
            client_random + server_hello.server_random,
        ).digest()
        signature = hmac.new(
            self.client_cert.public_key, transcript_hash, hashlib.sha256,
        ).digest()
        cv = CertificateVerify(client_certificate=self.client_cert, signature=signature)
        result = self.mtls_server.complete_handshake(session_id, cv, now=NOW)
        assert result.established
        assert result.client_subject == "device-alpha"

    def test_is_authenticated_after_handshake(self) -> None:
        client_random = b"\x02" * 32
        hello = ClientHello(client_random=client_random)
        session_id, server_hello = self.mtls_server.start_handshake(hello)
        assert not isinstance(server_hello, TLSAlert)

        transcript_hash = hashlib.sha256(
            client_random + server_hello.server_random,
        ).digest()
        signature = hmac.new(
            self.client_cert.public_key, transcript_hash, hashlib.sha256,
        ).digest()
        cv = CertificateVerify(client_certificate=self.client_cert, signature=signature)
        self.mtls_server.complete_handshake(session_id, cv, now=NOW)
        assert self.mtls_server.is_authenticated("device-alpha")
        assert not self.mtls_server.is_authenticated("unknown")

    def test_revoke_session(self) -> None:
        client_random = b"\x03" * 32
        hello = ClientHello(client_random=client_random)
        session_id, server_hello = self.mtls_server.start_handshake(hello)
        assert not isinstance(server_hello, TLSAlert)

        transcript_hash = hashlib.sha256(
            client_random + server_hello.server_random,
        ).digest()
        signature = hmac.new(
            self.client_cert.public_key, transcript_hash, hashlib.sha256,
        ).digest()
        cv = CertificateVerify(client_certificate=self.client_cert, signature=signature)
        self.mtls_server.complete_handshake(session_id, cv, now=NOW)
        assert self.mtls_server.revoke_session(session_id)
        assert not self.mtls_server.is_authenticated("device-alpha")

    def test_revoke_nonexistent_session(self) -> None:
        assert not self.mtls_server.revoke_session("nonexistent")

    def test_complete_unknown_session(self) -> None:
        cv = CertificateVerify(client_certificate=self.client_cert, signature=b"\x00" * 32)
        result = self.mtls_server.complete_handshake("unknown-id", cv, now=NOW)
        assert not result.established
        assert result.alert is not None

    def test_encrypt_decrypt_via_server(self) -> None:
        client_random = b"\x04" * 32
        hello = ClientHello(client_random=client_random)
        session_id, server_hello = self.mtls_server.start_handshake(hello)
        assert not isinstance(server_hello, TLSAlert)

        transcript_hash = hashlib.sha256(
            client_random + server_hello.server_random,
        ).digest()
        signature = hmac.new(
            self.client_cert.public_key, transcript_hash, hashlib.sha256,
        ).digest()
        cv = CertificateVerify(client_certificate=self.client_cert, signature=signature)
        self.mtls_server.complete_handshake(session_id, cv, now=NOW)

        encrypted = self.mtls_server.encrypt_for_client(session_id, b"hello device")
        assert encrypted is not None
        decrypted = self.mtls_server.decrypt_from_client(session_id, encrypted)
        assert decrypted == b"hello device"

    def test_encrypt_no_session(self) -> None:
        assert self.mtls_server.encrypt_for_client("none", b"x") is None

    def test_decrypt_no_session(self) -> None:
        msg = EncryptedMessage(nonce=b"\x00" * 12, ciphertext=b"x", mac=b"\x00" * 32)
        assert self.mtls_server.decrypt_from_client("none", msg) is None


# ---------------------------------------------------------------------------
# Convenience functions
# ---------------------------------------------------------------------------


class TestConvenience:
    def test_make_mtls_zone_setup(self) -> None:
        ca, server, cert, key = make_mtls_zone_setup(
            zone_name="z1", ca_name="MyCA", now=NOW, seed=b"conv",
        )
        assert ca.name == "MyCA"
        assert server.server_certificate.subject == "z1"
        assert cert.cert_type == CertificateType.SERVER

    def test_issue_client_certificate(self) -> None:
        ca = CertificateAuthority(name="CA", now=NOW, seed=b"ic")
        cert, key = issue_client_certificate(ca, "dev-1", now=NOW)
        assert cert.subject == "dev-1"
        assert cert.cert_type == CertificateType.CLIENT
        assert cert.extensions == {"device": "dev-1"}

    def test_client_handshake_no_server_cert(self) -> None:
        ca = CertificateAuthority(name="CA", now=NOW, seed=b"ch")
        cert, key = issue_client_certificate(ca, "d", now=NOW)
        from ipv8lab.mtls import ServerHello

        sh = ServerHello(server_random=b"\x00" * 32, server_certificate=None)
        result = client_handshake(ca, cert, key, sh, b"\x00" * 32, now=NOW)
        assert isinstance(result, TLSAlert)
        assert result.description == AlertDescription.HANDSHAKE_FAILURE

    def test_client_handshake_wrong_server_type(self) -> None:
        ca = CertificateAuthority(name="CA", now=NOW, seed=b"ch2")
        cert, key = issue_client_certificate(ca, "d", now=NOW)
        # Issue a CLIENT cert as server cert
        kp = KeyPair.from_seed(b"wrong")
        wrong = ca.issue_certificate("wrong", CertificateType.CLIENT, kp.public_key, now=NOW)
        from ipv8lab.mtls import ServerHello

        sh = ServerHello(server_random=b"\x00" * 32, server_certificate=wrong)
        result = client_handshake(ca, cert, key, sh, b"\x00" * 32, now=NOW)
        assert isinstance(result, TLSAlert)
        assert result.description == AlertDescription.BAD_CERTIFICATE


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class TestMTLSCLI:
    @pytest.fixture(autouse=True)
    def setup(self) -> None:
        from typer.testing import CliRunner

        from ipv8lab.cli.mtls_cli import app

        self.runner = CliRunner()
        self.app = app
        # Reset module state
        import ipv8lab.cli.mtls_cli as m

        m._ca = None
        m._mtls_server = None
        m._server_key = None

    def test_init(self) -> None:
        result = self.runner.invoke(self.app, ["init"])
        assert result.exit_code == 0
        assert "mTLS Zone Server Initialized" in result.output or "IPv8-Lab-CA" in result.output

    def test_init_json(self) -> None:
        result = self.runner.invoke(self.app, ["init", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["ca_name"] == "IPv8-Lab-CA"
        assert data["zone_name"] == "zone-primary"

    def test_issue(self) -> None:
        result = self.runner.invoke(self.app, ["issue", "my-device"])
        assert result.exit_code == 0
        assert "my-device" in result.output

    def test_issue_json(self) -> None:
        result = self.runner.invoke(self.app, ["issue", "dev-x", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["subject"] == "dev-x"
        assert data["type"] == "CLIENT"

    def test_verify(self) -> None:
        result = self.runner.invoke(self.app, ["verify", "test-dev"])
        assert result.exit_code == 0
        assert "VALID" in result.output

    def test_verify_json(self) -> None:
        result = self.runner.invoke(self.app, ["verify", "test-dev", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["valid"] is True

    def test_handshake(self) -> None:
        result = self.runner.invoke(self.app, ["handshake", "dev-1"])
        assert result.exit_code == 0
        assert "successful" in result.output or "ESTABLISHED" in result.output

    def test_handshake_json(self) -> None:
        result = self.runner.invoke(self.app, ["handshake", "dev-1", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["established"] is True
        assert data["client_subject"] == "dev-1"

    def test_encrypt(self) -> None:
        result = self.runner.invoke(self.app, ["encrypt", "dev-1", "secret-msg"])
        assert result.exit_code == 0
        assert "Ciphertext" in result.output

    def test_encrypt_json(self) -> None:
        result = self.runner.invoke(self.app, ["encrypt", "dev-1", "hello", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["plaintext"] == "hello"
        assert "ciphertext" in data
        assert "mac" in data

    def test_status(self) -> None:
        result = self.runner.invoke(self.app, ["status"])
        assert result.exit_code == 0
        assert "mTLS Status" in result.output or "IPv8-Lab-CA" in result.output

    def test_status_json(self) -> None:
        result = self.runner.invoke(self.app, ["status", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "ca_name" in data
        assert "issued_certificates" in data

    def test_revoke(self) -> None:
        result = self.runner.invoke(self.app, ["revoke", "2"])
        assert result.exit_code == 0

    def test_revoke_json(self) -> None:
        result = self.runner.invoke(self.app, ["revoke", "99", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["serial"] == 99

    def test_no_args(self) -> None:
        result = self.runner.invoke(self.app, [])
        assert result.exit_code in (0, 2)
