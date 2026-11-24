"""Vulnerability assessment: SSL/TLS audit.

Inspects a host's TLS configuration using the stdlib ``ssl`` module (plus
``cryptography`` for certificate parsing when available): negotiated protocol,
certificate validity/expiry, self-signed/hostname-mismatch issues, and whether
deprecated protocol versions are still accepted. Read-only — it only completes
handshakes, it does not attack the endpoint.
"""

from __future__ import annotations

import datetime as _dt
import socket
import ssl
from typing import Iterator

from aya.core.plugins import register
from aya.modules.base import BaseModule, Finding, ModuleContext, ModuleInput, Phase, Severity

LEGACY_PROTOCOLS = {
    "SSLv3": ssl.TLSVersion.SSLv3 if hasattr(ssl.TLSVersion, "SSLv3") else None,
    "TLSv1": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
}


@register
class SslAuditModule(BaseModule):
    id = "vuln.ssl_audit"
    name = "SSL/TLS Audit"
    phase = Phase.VULN_ASSESS
    description = "Check certificate validity and deprecated TLS protocol support."
    inputs = [
        ModuleInput("target", "Host"),
        ModuleInput("port", "Port", kind="int", default=443, required=False),
    ]

    def run(self, ctx: ModuleContext, params) -> Iterator[Finding]:
        host = params["target"].strip()
        port = int(params.get("port", 443) or 443)
        ctx.scope.require(host)
        timeout = ctx.settings.connect_timeout

        # --- certificate + negotiated protocol (verified handshake) ---
        ctx.gate()
        cert = None
        negotiated = ""
        verify_error = ""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ss:
                    cert = ss.getpeercert()
                    negotiated = ss.version()
        except ssl.SSLCertVerificationError as e:
            verify_error = str(e)
            # Re-handshake without verification to still read the cert.
            cert, negotiated = self._unverified(host, port, timeout)
        except Exception as e:
            yield Finding(title=f"TLS handshake failed on {host}:{port}",
                          target=host, severity=Severity.INFO, description=str(e))
            return

        if verify_error:
            yield Finding(
                title=f"TLS certificate verification failed for {host}:{port}",
                target=host, severity=Severity.MEDIUM,
                description=verify_error,
                remediation="Install a valid, trusted certificate matching the hostname.",
                cwe=["CWE-295"],
            )

        # --- expiry check ---
        if cert and cert.get("notAfter"):
            try:
                exp = _dt.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                days = (exp - _dt.datetime.utcnow()).days
                if days < 0:
                    yield Finding(title=f"TLS certificate EXPIRED on {host}:{port}",
                                  target=host, severity=Severity.HIGH,
                                  description=f"Expired {-days} day(s) ago ({cert['notAfter']}).",
                                  remediation="Renew the certificate immediately.",
                                  cwe=["CWE-298"])
                elif days < 30:
                    yield Finding(title=f"TLS certificate expiring soon on {host}:{port}",
                                  target=host, severity=Severity.LOW,
                                  description=f"Expires in {days} day(s).",
                                  remediation="Schedule certificate renewal.")
            except ValueError:
                pass

        # --- deprecated protocol acceptance ---
        accepted_legacy = []
        for name, ver in LEGACY_PROTOCOLS.items():
            if ver is None:
                continue
            if ctx.cancel.is_set():
                break
            ctx.gate()
            if self._accepts(host, port, ver, timeout):
                accepted_legacy.append(name)
        if accepted_legacy:
            yield Finding(
                title=f"Deprecated TLS protocol(s) accepted on {host}:{port}",
                target=host, severity=Severity.MEDIUM,
                description=f"Server negotiated: {', '.join(accepted_legacy)}.",
                remediation="Disable SSLv3/TLSv1.0/TLSv1.1; require TLSv1.2+.",
                cwe=["CWE-327"],
                refs=["https://datatracker.ietf.org/doc/html/rfc8996"],
            )

        subject = dict(x[0] for x in cert.get("subject", [])) if cert else {}
        issuer = dict(x[0] for x in cert.get("issuer", [])) if cert else {}
        yield Finding(
            title=f"TLS summary for {host}:{port}", target=host, severity=Severity.INFO,
            description=f"Negotiated protocol: {negotiated}.",
            evidence=(f"Subject: {subject}\nIssuer: {issuer}\n"
                      f"Valid until: {cert.get('notAfter') if cert else '?'}\n"
                      f"Protocol: {negotiated}\nLegacy accepted: {accepted_legacy}"),
            data={"protocol": negotiated, "legacy": accepted_legacy,
                  "subject": subject, "issuer": issuer},
        )

    @staticmethod
    def _unverified(host, port, timeout):
        ctx = ssl._create_unverified_context()
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ss:
                    return ss.getpeercert(binary_form=False) or {}, ss.version()
        except Exception:
            return {}, ""

    @staticmethod
    def _accepts(host, port, version, timeout) -> bool:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = version
            ctx.maximum_version = version
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    return True
        except (ssl.SSLError, OSError, ValueError):
            return False
