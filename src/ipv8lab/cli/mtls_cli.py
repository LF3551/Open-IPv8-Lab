# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""CLI commands for mTLS / encryption layer."""

from __future__ import annotations

import json
import time

import typer
from rich.console import Console
from rich.table import Table

from ipv8lab.mtls import (
    Certificate,
    CertificateAuthority,
    CertificateType,
    CertificateVerify,
    ClientHello,
    KeyPair,
    MTLSSession,
    ZoneServerMTLS,
    issue_client_certificate,
    make_mtls_zone_setup,
    perform_mtls_handshake,
)

app = typer.Typer(no_args_is_help=True)
console = Console()

# Module-level state
_ca: CertificateAuthority | None = None
_mtls_server: ZoneServerMTLS | None = None
_server_key: KeyPair | None = None


def _ensure_setup() -> tuple[CertificateAuthority, ZoneServerMTLS, KeyPair]:
    global _ca, _mtls_server, _server_key
    if _ca is None or _mtls_server is None or _server_key is None:
        _ca, _mtls_server, _, _server_key = make_mtls_zone_setup(
            seed=b"cli-deterministic",
            now=time.time(),
        )
    return _ca, _mtls_server, _server_key


@app.command("init")
def init_ca(
    ca_name: str = typer.Option("IPv8-Lab-CA", help="CA name."),
    zone_name: str = typer.Option("zone-primary", help="Zone Server name."),
    validity_days: int = typer.Option(365, help="Certificate validity in days."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Initialize mTLS Certificate Authority and Zone Server."""
    global _ca, _mtls_server, _server_key
    now = time.time()
    _ca, _mtls_server, server_cert, _server_key = make_mtls_zone_setup(
        zone_name=zone_name,
        ca_name=ca_name,
        validity_days=validity_days,
        now=now,
        seed=b"cli-deterministic",
    )

    if as_json:
        typer.echo(json.dumps({
            "ca_name": ca_name,
            "zone_name": zone_name,
            "validity_days": validity_days,
            "ca_fingerprint": _ca.ca_certificate.fingerprint(),
            "server_fingerprint": server_cert.fingerprint(),
            "server_subject": server_cert.subject,
        }, indent=2))
        return

    table = Table(title="mTLS Zone Server Initialized", show_header=False, box=None)
    table.add_column(style="bold cyan", min_width=20)
    table.add_column()
    table.add_row("CA", ca_name)
    table.add_row("CA fingerprint", _ca.ca_certificate.fingerprint()[:32] + "...")
    table.add_row("Zone Server", zone_name)
    table.add_row("Server fingerprint", server_cert.fingerprint()[:32] + "...")
    table.add_row("Validity", f"{validity_days} days")
    table.add_row("Status", "[green]Active[/green]")
    console.print(table)


@app.command("issue")
def issue_cert(
    device: str = typer.Argument(help="Device name / subject."),
    cert_type: str = typer.Option("client", help="Certificate type: client or server."),
    validity_days: int = typer.Option(90, help="Certificate validity in days."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Issue a certificate for a device."""
    ca, _, _ = _ensure_setup()
    ctype = CertificateType.CLIENT if cert_type.lower() == "client" else CertificateType.SERVER
    now = time.time()
    if ctype == CertificateType.CLIENT:
        cert, key = issue_client_certificate(ca, device, validity_days=validity_days, now=now)
    else:
        key = KeyPair.from_seed(device.encode())
        cert = ca.issue_certificate(
            subject=device,
            cert_type=CertificateType.SERVER,
            public_key=key.public_key,
            validity_days=validity_days,
            now=now,
        )

    if as_json:
        typer.echo(json.dumps(cert.to_dict(), indent=2))
        return

    table = Table(title=f"Certificate Issued — {device}", show_header=False, box=None)
    table.add_column(style="bold cyan", min_width=20)
    table.add_column()
    table.add_row("Subject", cert.subject)
    table.add_row("Type", cert.cert_type.name)
    table.add_row("Serial", str(cert.serial_number))
    table.add_row("Issuer", cert.issuer)
    table.add_row("Fingerprint", cert.fingerprint()[:32] + "...")
    table.add_row("Validity", f"{validity_days} days")
    console.print(table)


@app.command("verify")
def verify_cert(
    device: str = typer.Argument(help="Device name whose cert to verify."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Verify a device certificate against the CA."""
    ca, _, _ = _ensure_setup()
    now = time.time()
    cert, _ = issue_client_certificate(ca, device, now=now)
    result = ca.verify_certificate(cert, now=now)

    if as_json:
        typer.echo(json.dumps({
            "subject": device,
            "valid": result.valid,
            "reason": result.reason,
            "fingerprint": cert.fingerprint(),
        }, indent=2))
        return

    if result.valid:
        console.print(f"[green]VALID[/green] — {device} (serial #{cert.serial_number})")
    else:
        console.print(f"[red]INVALID[/red] — {device}: {result.reason}")


@app.command("handshake")
def do_handshake(
    device: str = typer.Argument(help="Client device name (auto-issued cert; handshakes against zone server)."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Perform full mTLS handshake simulation (client device vs. zone server)."""
    ca, mtls_server, server_key = _ensure_setup()
    now = time.time()
    client_cert, client_key = issue_client_certificate(ca, device, now=now)
    result = perform_mtls_handshake(
        ca=ca,
        server_cert=mtls_server.server_certificate,
        server_key=server_key,
        client_cert=client_cert,
        client_key=client_key,
        now=now,
    )

    if as_json:
        data: dict[str, object] = {
            "state": result.state.name,
            "established": result.established,
            "client_subject": result.client_subject,
            "server_subject": result.server_subject,
            "cipher": result.cipher,
        }
        if result.alert:
            data["alert"] = {
                "level": result.alert.level.name,
                "description": result.alert.description.name,
                "message": result.alert.message,
            }
        typer.echo(json.dumps(data, indent=2))
        return

    if result.established:
        console.print("[green]mTLS handshake successful[/green]")
        console.print(f"  Client: {result.client_subject}")
        console.print(f"  Server: {result.server_subject}")
        console.print(f"  Cipher: {result.cipher}")
        console.print(f"  Session key: {result.session_key.hex()[:32]}...")
    else:
        console.print("[red]mTLS handshake FAILED[/red]")
        if result.alert:
            console.print(f"  Alert: {result.alert.description.name}")
            console.print(f"  Reason: {result.alert.message}")


@app.command("encrypt")
def encrypt_message(
    device: str = typer.Argument(help="Client device name."),
    message: str = typer.Argument(help="Message to encrypt."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Encrypt a message over an established mTLS session."""
    ca, mtls_server, server_key = _ensure_setup()
    now = time.time()
    client_cert, client_key = issue_client_certificate(ca, device, now=now)

    # Perform handshake first
    result = perform_mtls_handshake(
        ca=ca,
        server_cert=mtls_server.server_certificate,
        server_key=server_key,
        client_cert=client_cert,
        client_key=client_key,
        now=now,
    )
    if not result.established:
        console.print("[red]Handshake failed — cannot encrypt.[/red]")
        raise typer.Exit(1)

    # Create session for encryption
    session = _build_session(ca, mtls_server, server_key, client_cert, client_key, now)
    encrypted = session.encrypt(message.encode())

    if as_json:
        typer.echo(json.dumps({
            "plaintext": message,
            "nonce": encrypted.nonce.hex(),
            "ciphertext": encrypted.ciphertext.hex(),
            "mac": encrypted.mac.hex(),
            "cipher": "TLS_AES_256_GCM_SHA384",
        }, indent=2))
        return

    console.print(f"[bold]Plaintext:[/bold]  {message}")
    console.print(f"[bold]Nonce:[/bold]      {encrypted.nonce.hex()}")
    console.print(f"[bold]Ciphertext:[/bold] {encrypted.ciphertext.hex()}")
    console.print(f"[bold]MAC:[/bold]        {encrypted.mac.hex()[:32]}...")


@app.command("status")
def show_status(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Show mTLS Zone Server status."""
    ca, mtls_server, _ = _ensure_setup()

    if as_json:
        typer.echo(json.dumps({
            "ca_name": ca.name,
            "issued_certificates": ca.issued_count,
            "revoked_certificates": len(ca.revoked_serials),
            "active_sessions": mtls_server.active_session_count,
            "authenticated_clients": sorted(mtls_server.authenticated_clients),
            "server_subject": mtls_server.server_certificate.subject,
        }, indent=2))
        return

    table = Table(title="mTLS Status", show_header=False, box=None)
    table.add_column(style="bold cyan", min_width=22)
    table.add_column()
    table.add_row("CA", ca.name)
    table.add_row("Issued certs", str(ca.issued_count))
    table.add_row("Revoked", str(len(ca.revoked_serials)))
    table.add_row("Active sessions", str(mtls_server.active_session_count))
    table.add_row("Authenticated", str(sorted(mtls_server.authenticated_clients)))
    table.add_row("Server", mtls_server.server_certificate.subject)
    console.print(table)


@app.command("revoke")
def revoke(
    serial: int = typer.Argument(help="Certificate serial number to revoke."),
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Revoke a certificate by serial number."""
    ca, _, _ = _ensure_setup()
    success = ca.revoke_certificate(serial)

    if as_json:
        typer.echo(json.dumps({
            "serial": serial,
            "revoked": success,
        }, indent=2))
        return

    if success:
        console.print(f"[green]✓[/green] Certificate #{serial} revoked.")
    else:
        console.print(f"[red]✗[/red] Certificate #{serial} not found.")


def _build_session(
    ca: CertificateAuthority,
    mtls_server: ZoneServerMTLS,
    server_key: KeyPair,
    client_cert: Certificate,
    client_key: KeyPair,
    now: float,
) -> MTLSSession:
    """Build an established session for encrypt/decrypt operations."""
    import hashlib as _hashlib
    import hmac as _hmac
    import secrets as _secrets

    session = MTLSSession(ca=ca, server_cert=mtls_server.server_certificate, server_key=server_key)
    client_random = _secrets.token_bytes(32)
    hello = ClientHello(client_random=client_random)
    server_hello = session.process_client_hello(hello)

    transcript_hash = _hashlib.sha256(client_random + server_hello.server_random).digest()  # type: ignore[union-attr]
    signature = _hmac.new(client_cert.public_key, transcript_hash, _hashlib.sha256).digest()
    cert_verify = CertificateVerify(client_certificate=client_cert, signature=signature)
    session.process_certificate_verify(cert_verify, now=now)
    return session
