# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""mTLS / encryption layer for Zone Server authentication.

Implements mutual TLS simulation for device-to-Zone-Server communication:
- Certificate Authority (CA) with key generation and cert signing
- X.509-like certificate structure (mock, deterministic for testing)
- mTLS handshake protocol (ClientHello → ServerHello → CertVerify → Finished)
- Encrypted channel with HMAC integrity verification
- Zone Server integration for certificate-based device authentication

All crypto uses hashlib/hmac/secrets — no external dependencies required.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any


# ---------------------------------------------------------------------------
# Certificate types
# ---------------------------------------------------------------------------


class CertificateType(Enum):
    """Certificate type."""

    CA = auto()
    SERVER = auto()
    CLIENT = auto()


class HandshakeState(Enum):
    """mTLS handshake state machine."""

    IDLE = auto()
    CLIENT_HELLO_SENT = auto()
    SERVER_HELLO_SENT = auto()
    CERT_VERIFY = auto()
    ESTABLISHED = auto()
    FAILED = auto()


class AlertLevel(Enum):
    """TLS alert level."""

    WARNING = auto()
    FATAL = auto()


class AlertDescription(Enum):
    """TLS alert description."""

    CERTIFICATE_EXPIRED = auto()
    CERTIFICATE_UNKNOWN = auto()
    CERTIFICATE_REVOKED = auto()
    BAD_CERTIFICATE = auto()
    HANDSHAKE_FAILURE = auto()
    DECRYPT_ERROR = auto()
    UNKNOWN_CA = auto()


@dataclass(frozen=True, slots=True)
class KeyPair:
    """Simulated asymmetric key pair (Ed25519-like mock).

    In production this would be an actual Ed25519/ECDSA key pair.
    Here we use random bytes + HMAC for deterministic testing.
    """

    private_key: bytes
    public_key: bytes

    @staticmethod
    def generate(rng: secrets.SystemRandom | None = None) -> KeyPair:
        """Generate a new key pair."""
        if rng is None:
            private = secrets.token_bytes(32)
        else:
            private = bytes(rng.randbelow(256) for _ in range(32))
        public = hashlib.sha256(b"pub:" + private).digest()
        return KeyPair(private_key=private, public_key=public)

    @staticmethod
    def from_seed(seed: bytes) -> KeyPair:
        """Generate deterministic key pair from seed (for testing)."""
        private = hashlib.sha256(b"priv:" + seed).digest()
        public = hashlib.sha256(b"pub:" + private).digest()
        return KeyPair(private_key=private, public_key=public)

    def sign(self, data: bytes) -> bytes:
        """Sign data with private key (HMAC-SHA256 mock)."""
        return hmac.new(self.private_key, data, hashlib.sha256).digest()

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Verify signature with public key.

        For mock purposes, we recompute with private key.  In real
        implementations this would use the public key alone.
        """
        expected = hmac.new(self.private_key, data, hashlib.sha256).digest()
        return hmac.compare_digest(expected, signature)


@dataclass(frozen=True, slots=True)
class Certificate:
    """X.509-like certificate (simplified mock).

    Fields follow RFC 5280 structure but are simplified for simulation.
    """

    serial_number: int
    subject: str
    issuer: str
    cert_type: CertificateType
    public_key: bytes
    not_before: float
    not_after: float
    signature: bytes = b""
    extensions: dict[str, str] = field(default_factory=dict)

    def is_expired(self, now: float | None = None) -> bool:
        if now is None:
            now = time.time()
        return now >= self.not_after

    def is_not_yet_valid(self, now: float | None = None) -> bool:
        if now is None:
            now = time.time()
        return now < self.not_before

    def is_valid_at(self, now: float | None = None) -> bool:
        if now is None:
            now = time.time()
        return self.not_before <= now < self.not_after

    def fingerprint(self) -> str:
        """SHA-256 fingerprint of the certificate."""
        data = self._signable_bytes()
        return hashlib.sha256(data).hexdigest()

    def _signable_bytes(self) -> bytes:
        """Canonical byte representation for signing."""
        parts = [
            str(self.serial_number).encode(),
            self.subject.encode(),
            self.issuer.encode(),
            self.cert_type.name.encode(),
            self.public_key,
            str(self.not_before).encode(),
            str(self.not_after).encode(),
        ]
        return b"|".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "serial_number": self.serial_number,
            "subject": self.subject,
            "issuer": self.issuer,
            "type": self.cert_type.name,
            "public_key": self.public_key.hex(),
            "not_before": self.not_before,
            "not_after": self.not_after,
            "fingerprint": self.fingerprint(),
            "extensions": dict(self.extensions),
        }


@dataclass(frozen=True, slots=True)
class TLSAlert:
    """TLS alert message."""

    level: AlertLevel
    description: AlertDescription
    message: str = ""


# ---------------------------------------------------------------------------
# Certificate Authority
# ---------------------------------------------------------------------------


class CertificateAuthority:
    """Simulated Certificate Authority for Zone Server mTLS.

    Issues server and client certificates, maintains CRL.
    """

    def __init__(
        self,
        name: str = "IPv8-Lab-CA",
        validity_days: int = 365,
        now: float | None = None,
        seed: bytes | None = None,
    ) -> None:
        self.name = name
        self._next_serial = 1
        self._validity_days = validity_days
        if seed is not None:
            self._key_pair = KeyPair.from_seed(seed)
        else:
            self._key_pair = KeyPair.generate()
        self._revoked: set[int] = set()
        self._issued: dict[int, Certificate] = {}
        _now = now if now is not None else time.time()
        self._ca_cert = self._issue_self_signed(_now)

    def _issue_self_signed(self, now: float) -> Certificate:
        """Issue self-signed CA certificate."""
        serial = self._next_serial
        self._next_serial += 1
        cert = Certificate(
            serial_number=serial,
            subject=self.name,
            issuer=self.name,
            cert_type=CertificateType.CA,
            public_key=self._key_pair.public_key,
            not_before=now,
            not_after=now + self._validity_days * 86400,
        )
        sig = self._key_pair.sign(cert._signable_bytes())
        signed_cert = Certificate(
            serial_number=cert.serial_number,
            subject=cert.subject,
            issuer=cert.issuer,
            cert_type=cert.cert_type,
            public_key=cert.public_key,
            not_before=cert.not_before,
            not_after=cert.not_after,
            signature=sig,
        )
        self._issued[serial] = signed_cert
        return signed_cert

    @property
    def ca_certificate(self) -> Certificate:
        return self._ca_cert

    @property
    def public_key(self) -> bytes:
        return self._key_pair.public_key

    @property
    def issued_count(self) -> int:
        return len(self._issued)

    @property
    def revoked_serials(self) -> set[int]:
        return set(self._revoked)

    def issue_certificate(
        self,
        subject: str,
        cert_type: CertificateType,
        public_key: bytes,
        validity_days: int | None = None,
        now: float | None = None,
        extensions: dict[str, str] | None = None,
    ) -> Certificate:
        """Issue a signed certificate."""
        _now = now if now is not None else time.time()
        _days = validity_days if validity_days is not None else self._validity_days
        serial = self._next_serial
        self._next_serial += 1
        cert = Certificate(
            serial_number=serial,
            subject=subject,
            issuer=self.name,
            cert_type=cert_type,
            public_key=public_key,
            not_before=_now,
            not_after=_now + _days * 86400,
            extensions=extensions or {},
        )
        sig = self._key_pair.sign(cert._signable_bytes())
        signed_cert = Certificate(
            serial_number=cert.serial_number,
            subject=cert.subject,
            issuer=cert.issuer,
            cert_type=cert.cert_type,
            public_key=cert.public_key,
            not_before=cert.not_before,
            not_after=cert.not_after,
            signature=sig,
            extensions=cert.extensions,
        )
        self._issued[serial] = signed_cert
        return signed_cert

    def verify_certificate(self, cert: Certificate, now: float | None = None) -> CertVerifyResult:
        """Verify a certificate against this CA."""
        if cert.issuer != self.name:
            return CertVerifyResult(
                valid=False,
                reason=f"unknown issuer: {cert.issuer!r} (expected {self.name!r})",
            )
        if cert.serial_number in self._revoked:
            return CertVerifyResult(valid=False, reason="certificate revoked")
        expected_sig = self._key_pair.sign(cert._signable_bytes())
        if not hmac.compare_digest(cert.signature, expected_sig):
            return CertVerifyResult(valid=False, reason="invalid signature")
        if not cert.is_valid_at(now):
            if cert.is_expired(now):
                return CertVerifyResult(valid=False, reason="certificate expired")
            return CertVerifyResult(valid=False, reason="certificate not yet valid")
        return CertVerifyResult(valid=True)

    def revoke_certificate(self, serial_number: int) -> bool:
        """Add certificate to CRL."""
        if serial_number not in self._issued:
            return False
        self._revoked.add(serial_number)
        return True

    def is_revoked(self, serial_number: int) -> bool:
        return serial_number in self._revoked

    def get_certificate(self, serial_number: int) -> Certificate | None:
        return self._issued.get(serial_number)


@dataclass(frozen=True, slots=True)
class CertVerifyResult:
    """Result of certificate verification."""

    valid: bool
    reason: str = ""


# ---------------------------------------------------------------------------
# mTLS Handshake
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ClientHello:
    """TLS ClientHello message."""

    client_random: bytes
    supported_ciphers: tuple[str, ...] = ("TLS_AES_256_GCM_SHA384",)
    sni: str = ""


@dataclass(frozen=True, slots=True)
class ServerHello:
    """TLS ServerHello message."""

    server_random: bytes
    selected_cipher: str = "TLS_AES_256_GCM_SHA384"
    server_certificate: Certificate | None = None


@dataclass(frozen=True, slots=True)
class CertificateVerify:
    """CertificateVerify message with client cert + signature."""

    client_certificate: Certificate
    signature: bytes  # signature over handshake transcript


@dataclass(frozen=True, slots=True)
class Finished:
    """Handshake Finished message."""

    verify_data: bytes  # HMAC over handshake transcript


@dataclass(frozen=True, slots=True)
class HandshakeResult:
    """Result of mTLS handshake."""

    state: HandshakeState
    session_key: bytes = b""
    client_subject: str = ""
    server_subject: str = ""
    alert: TLSAlert | None = None
    cipher: str = ""

    @property
    def established(self) -> bool:
        return self.state == HandshakeState.ESTABLISHED


# ---------------------------------------------------------------------------
# mTLS Session
# ---------------------------------------------------------------------------


class MTLSSession:
    """Simulated mTLS session between client and server.

    Performs mutual authentication: server presents cert, client presents cert.
    Derives session key from shared random values for encrypted channel.
    """

    def __init__(
        self,
        ca: CertificateAuthority,
        server_cert: Certificate,
        server_key: KeyPair,
    ) -> None:
        self._ca = ca
        self._server_cert = server_cert
        self._server_key = server_key
        self._state = HandshakeState.IDLE
        self._client_random: bytes = b""
        self._server_random: bytes = b""
        self._session_key: bytes = b""
        self._client_subject: str = ""
        self._transcript: list[bytes] = []

    @property
    def state(self) -> HandshakeState:
        return self._state

    @property
    def session_key(self) -> bytes:
        return self._session_key

    @property
    def client_subject(self) -> str:
        return self._client_subject

    def process_client_hello(self, hello: ClientHello) -> ServerHello | TLSAlert:
        """Process ClientHello, return ServerHello or alert."""
        if self._state != HandshakeState.IDLE:
            return TLSAlert(
                AlertLevel.FATAL,
                AlertDescription.HANDSHAKE_FAILURE,
                "unexpected ClientHello",
            )
        self._client_random = hello.client_random
        self._server_random = secrets.token_bytes(32)
        self._transcript.append(hello.client_random)
        self._transcript.append(self._server_random)
        self._state = HandshakeState.SERVER_HELLO_SENT
        return ServerHello(
            server_random=self._server_random,
            selected_cipher=hello.supported_ciphers[0] if hello.supported_ciphers else "TLS_AES_256_GCM_SHA384",
            server_certificate=self._server_cert,
        )

    def process_certificate_verify(
        self,
        cert_verify: CertificateVerify,
        now: float | None = None,
    ) -> Finished | TLSAlert:
        """Process client CertificateVerify, return Finished or alert."""
        if self._state != HandshakeState.SERVER_HELLO_SENT:
            return TLSAlert(
                AlertLevel.FATAL,
                AlertDescription.HANDSHAKE_FAILURE,
                "unexpected CertificateVerify",
            )

        # Verify client certificate against CA
        verify_result = self._ca.verify_certificate(cert_verify.client_certificate, now=now)
        if not verify_result.valid:
            self._state = HandshakeState.FAILED
            desc = AlertDescription.BAD_CERTIFICATE
            if "expired" in verify_result.reason:
                desc = AlertDescription.CERTIFICATE_EXPIRED
            elif "revoked" in verify_result.reason:
                desc = AlertDescription.CERTIFICATE_REVOKED
            elif "unknown" in verify_result.reason:
                desc = AlertDescription.UNKNOWN_CA
            return TLSAlert(AlertLevel.FATAL, desc, verify_result.reason)

        # Verify client certificate is CLIENT type
        if cert_verify.client_certificate.cert_type != CertificateType.CLIENT:
            self._state = HandshakeState.FAILED
            return TLSAlert(
                AlertLevel.FATAL,
                AlertDescription.BAD_CERTIFICATE,
                "expected CLIENT certificate",
            )

        # Verify signature over transcript
        transcript_hash = hashlib.sha256(b"".join(self._transcript)).digest()
        # We trust cert is valid since CA verified it; signature is mock
        expected_sig = hmac.new(
            cert_verify.client_certificate.public_key,
            transcript_hash,
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(cert_verify.signature, expected_sig):
            self._state = HandshakeState.FAILED
            return TLSAlert(
                AlertLevel.FATAL,
                AlertDescription.DECRYPT_ERROR,
                "certificate verify signature mismatch",
            )

        # Derive session key
        self._session_key = self._derive_session_key()
        self._client_subject = cert_verify.client_certificate.subject
        self._state = HandshakeState.ESTABLISHED

        verify_data = hmac.new(
            self._session_key, transcript_hash, hashlib.sha256,
        ).digest()
        return Finished(verify_data=verify_data)

    def _derive_session_key(self) -> bytes:
        """Derive session key from handshake material (HKDF-like)."""
        material = self._client_random + self._server_random + self._server_key.private_key
        return hashlib.sha256(b"session-key:" + material).digest()

    def encrypt(self, plaintext: bytes) -> EncryptedMessage:
        """Encrypt message with session key."""
        if self._state != HandshakeState.ESTABLISHED:
            msg = "session not established"
            raise RuntimeError(msg)
        nonce = secrets.token_bytes(12)
        # XOR-based stream cipher mock (NOT production-safe)
        keystream = hashlib.sha256(self._session_key + nonce).digest()
        ciphertext = bytes(p ^ keystream[i % 32] for i, p in enumerate(plaintext))
        mac = hmac.new(self._session_key, nonce + ciphertext, hashlib.sha256).digest()
        return EncryptedMessage(nonce=nonce, ciphertext=ciphertext, mac=mac)

    def decrypt(self, msg: EncryptedMessage) -> bytes | None:
        """Decrypt message. Returns None if integrity check fails."""
        if self._state != HandshakeState.ESTABLISHED:
            err = "session not established"
            raise RuntimeError(err)
        expected_mac = hmac.new(
            self._session_key, msg.nonce + msg.ciphertext, hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(msg.mac, expected_mac):
            return None
        keystream = hashlib.sha256(self._session_key + msg.nonce).digest()
        plaintext = bytes(c ^ keystream[i % 32] for i, c in enumerate(msg.ciphertext))
        return plaintext


@dataclass(frozen=True, slots=True)
class EncryptedMessage:
    """Encrypted message with nonce and MAC."""

    nonce: bytes
    ciphertext: bytes
    mac: bytes


# ---------------------------------------------------------------------------
# Client-side handshake helper
# ---------------------------------------------------------------------------


def client_handshake(
    ca: CertificateAuthority,
    client_cert: Certificate,
    client_key: KeyPair,
    server_hello: ServerHello,
    client_random: bytes,
    now: float | None = None,
) -> CertificateVerify | TLSAlert:
    """Client-side: verify server cert and produce CertificateVerify.

    Called after receiving ServerHello from server.
    """
    # Verify server certificate
    if server_hello.server_certificate is None:
        return TLSAlert(
            AlertLevel.FATAL,
            AlertDescription.HANDSHAKE_FAILURE,
            "server did not present certificate",
        )
    verify_result = ca.verify_certificate(server_hello.server_certificate, now=now)
    if not verify_result.valid:
        desc = AlertDescription.BAD_CERTIFICATE
        if "expired" in verify_result.reason:
            desc = AlertDescription.CERTIFICATE_EXPIRED
        elif "revoked" in verify_result.reason:
            desc = AlertDescription.CERTIFICATE_REVOKED
        elif "unknown" in verify_result.reason:
            desc = AlertDescription.UNKNOWN_CA
        return TLSAlert(AlertLevel.FATAL, desc, verify_result.reason)

    # Verify server certificate is SERVER type
    if server_hello.server_certificate.cert_type != CertificateType.SERVER:
        return TLSAlert(
            AlertLevel.FATAL,
            AlertDescription.BAD_CERTIFICATE,
            "expected SERVER certificate",
        )

    # Sign transcript with client key
    transcript_hash = hashlib.sha256(client_random + server_hello.server_random).digest()
    signature = hmac.new(
        client_cert.public_key,
        transcript_hash,
        hashlib.sha256,
    ).digest()
    return CertificateVerify(client_certificate=client_cert, signature=signature)


# ---------------------------------------------------------------------------
# Full handshake convenience
# ---------------------------------------------------------------------------


def perform_mtls_handshake(
    ca: CertificateAuthority,
    server_cert: Certificate,
    server_key: KeyPair,
    client_cert: Certificate,
    client_key: KeyPair,
    now: float | None = None,
) -> HandshakeResult:
    """Perform full mTLS handshake between client and server.

    Returns HandshakeResult with session key if successful.
    """
    session = MTLSSession(ca=ca, server_cert=server_cert, server_key=server_key)

    # Step 1: ClientHello
    client_random = secrets.token_bytes(32)
    hello = ClientHello(client_random=client_random, sni=server_cert.subject)
    server_hello = session.process_client_hello(hello)
    if isinstance(server_hello, TLSAlert):
        return HandshakeResult(
            state=HandshakeState.FAILED,
            alert=server_hello,
        )

    # Step 2: Client verifies server + sends CertificateVerify
    cert_verify = client_handshake(
        ca=ca,
        client_cert=client_cert,
        client_key=client_key,
        server_hello=server_hello,
        client_random=client_random,
        now=now,
    )
    if isinstance(cert_verify, TLSAlert):
        return HandshakeResult(
            state=HandshakeState.FAILED,
            alert=cert_verify,
        )

    # Step 3: Server verifies client cert
    finished = session.process_certificate_verify(cert_verify, now=now)
    if isinstance(finished, TLSAlert):
        return HandshakeResult(
            state=HandshakeState.FAILED,
            alert=finished,
        )

    return HandshakeResult(
        state=HandshakeState.ESTABLISHED,
        session_key=session.session_key,
        client_subject=session.client_subject,
        server_subject=server_cert.subject,
        cipher=server_hello.selected_cipher,
    )


# ---------------------------------------------------------------------------
# Zone Server mTLS integration
# ---------------------------------------------------------------------------


class ZoneServerMTLS:
    """mTLS layer for Zone Server authentication.

    Wraps a Zone Server pair with certificate-based mutual authentication.
    Devices must present a valid client certificate signed by the zone CA
    to communicate with the Zone Server.
    """

    def __init__(
        self,
        ca: CertificateAuthority,
        server_cert: Certificate,
        server_key: KeyPair,
    ) -> None:
        self._ca = ca
        self._server_cert = server_cert
        self._server_key = server_key
        self._active_sessions: dict[str, MTLSSession] = {}
        self._authenticated_clients: set[str] = set()

    @property
    def ca(self) -> CertificateAuthority:
        return self._ca

    @property
    def server_certificate(self) -> Certificate:
        return self._server_cert

    @property
    def active_session_count(self) -> int:
        return len(self._active_sessions)

    @property
    def authenticated_clients(self) -> set[str]:
        return set(self._authenticated_clients)

    def start_handshake(self, client_hello: ClientHello) -> tuple[str, ServerHello | TLSAlert]:
        """Start mTLS handshake for a new client connection.

        Returns (session_id, ServerHello | TLSAlert).
        """
        session_id = secrets.token_hex(16)
        session = MTLSSession(
            ca=self._ca,
            server_cert=self._server_cert,
            server_key=self._server_key,
        )
        result = session.process_client_hello(client_hello)
        if isinstance(result, TLSAlert):
            return session_id, result
        self._active_sessions[session_id] = session
        return session_id, result

    def complete_handshake(
        self,
        session_id: str,
        cert_verify: CertificateVerify,
        now: float | None = None,
    ) -> HandshakeResult:
        """Complete mTLS handshake with client certificate verification."""
        session = self._active_sessions.get(session_id)
        if session is None:
            return HandshakeResult(
                state=HandshakeState.FAILED,
                alert=TLSAlert(
                    AlertLevel.FATAL,
                    AlertDescription.HANDSHAKE_FAILURE,
                    f"unknown session: {session_id}",
                ),
            )
        finished = session.process_certificate_verify(cert_verify, now=now)
        if isinstance(finished, TLSAlert):
            del self._active_sessions[session_id]
            return HandshakeResult(state=HandshakeState.FAILED, alert=finished)

        self._authenticated_clients.add(session.client_subject)
        return HandshakeResult(
            state=HandshakeState.ESTABLISHED,
            session_key=session.session_key,
            client_subject=session.client_subject,
            server_subject=self._server_cert.subject,
            cipher="TLS_AES_256_GCM_SHA384",
        )

    def is_authenticated(self, subject: str) -> bool:
        """Check if a client subject has been authenticated."""
        return subject in self._authenticated_clients

    def revoke_session(self, session_id: str) -> bool:
        """Revoke an active session."""
        if session_id in self._active_sessions:
            session = self._active_sessions.pop(session_id)
            self._authenticated_clients.discard(session.client_subject)
            return True
        return False

    def encrypt_for_client(self, session_id: str, plaintext: bytes) -> EncryptedMessage | None:
        """Encrypt data for a specific client session."""
        session = self._active_sessions.get(session_id)
        if session is None or session.state != HandshakeState.ESTABLISHED:
            return None
        return session.encrypt(plaintext)

    def decrypt_from_client(self, session_id: str, msg: EncryptedMessage) -> bytes | None:
        """Decrypt data from a specific client session."""
        session = self._active_sessions.get(session_id)
        if session is None or session.state != HandshakeState.ESTABLISHED:
            return None
        return session.decrypt(msg)


# ---------------------------------------------------------------------------
# Convenience: create full mTLS-protected Zone Server setup
# ---------------------------------------------------------------------------


def make_mtls_zone_setup(
    zone_name: str = "zone-primary",
    ca_name: str = "IPv8-Lab-CA",
    validity_days: int = 365,
    now: float | None = None,
    seed: bytes | None = None,
) -> tuple[CertificateAuthority, ZoneServerMTLS, Certificate, KeyPair]:
    """Create a complete mTLS-protected Zone Server setup.

    Returns (ca, mtls_server, server_cert, server_key).
    """
    _now = now if now is not None else time.time()
    ca = CertificateAuthority(name=ca_name, validity_days=validity_days, now=_now, seed=seed)
    server_key = KeyPair.from_seed(zone_name.encode()) if seed else KeyPair.generate()
    server_cert = ca.issue_certificate(
        subject=zone_name,
        cert_type=CertificateType.SERVER,
        public_key=server_key.public_key,
        validity_days=validity_days,
        now=_now,
    )
    mtls_server = ZoneServerMTLS(ca=ca, server_cert=server_cert, server_key=server_key)
    return ca, mtls_server, server_cert, server_key


def issue_client_certificate(
    ca: CertificateAuthority,
    device_name: str,
    validity_days: int = 90,
    now: float | None = None,
    seed: bytes | None = None,
) -> tuple[Certificate, KeyPair]:
    """Issue a client certificate for a device.

    Returns (client_cert, client_key).
    """
    if seed is not None:
        client_key = KeyPair.from_seed(seed)
    else:
        client_key = KeyPair.from_seed(device_name.encode())
    client_cert = ca.issue_certificate(
        subject=device_name,
        cert_type=CertificateType.CLIENT,
        public_key=client_key.public_key,
        validity_days=validity_days,
        now=now,
        extensions={"device": device_name},
    )
    return client_cert, client_key
