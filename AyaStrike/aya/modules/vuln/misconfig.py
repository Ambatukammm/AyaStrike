"""Vulnerability assessment: common misconfiguration checks.

Cross-references the workspace service inventory for classically risky
exposures — plaintext/management services reachable, databases exposed to a
broad scope, default-credential-prone services — and reports them as findings
with remediation. This reasons over already-collected data; it does not probe
further or attempt authentication.
"""

from __future__ import annotations

from typing import Iterator

from aya.core.plugins import register
from aya.modules.base import BaseModule, Finding, ModuleContext, ModuleInput, Phase, Severity

# port -> (label, severity, why, remediation, cwe)
RISKY_PORTS = {
    21:   ("FTP", Severity.MEDIUM, "Plaintext credentials in transit.",
           "Use SFTP/FTPS or disable FTP.", "CWE-319"),
    23:   ("Telnet", Severity.HIGH, "Plaintext remote administration.",
           "Disable Telnet; use SSH.", "CWE-319"),
    69:   ("TFTP", Severity.MEDIUM, "Unauthenticated file transfer.",
           "Disable TFTP or restrict by firewall.", "CWE-306"),
    135:  ("MSRPC", Severity.LOW, "RPC endpoint mapper exposed.",
           "Restrict to management networks.", "CWE-284"),
    445:  ("SMB", Severity.MEDIUM, "File sharing exposed.",
           "Restrict SMB to trusted networks; disable SMBv1.", "CWE-284"),
    1433: ("MSSQL", Severity.HIGH, "Database directly reachable.",
           "Firewall the database; never expose to untrusted networks.", "CWE-284"),
    3306: ("MySQL", Severity.HIGH, "Database directly reachable.",
           "Bind to localhost / firewall the database.", "CWE-284"),
    5432: ("PostgreSQL", Severity.HIGH, "Database directly reachable.",
           "Restrict pg_hba.conf and firewall the port.", "CWE-284"),
    6379: ("Redis", Severity.CRITICAL, "Redis often has no auth by default.",
           "Enable 'requirepass', bind to localhost, enable protected-mode.", "CWE-306"),
    9200: ("Elasticsearch", Severity.CRITICAL, "ES exposes data with no auth by default.",
           "Enable security/auth; never expose ES to untrusted networks.", "CWE-306"),
    11211:("Memcached", Severity.HIGH, "Memcached is unauthenticated + DDoS amplifier.",
           "Bind to localhost; disable UDP.", "CWE-306"),
    27017:("MongoDB", Severity.CRITICAL, "MongoDB historically shipped with no auth.",
           "Enable authentication and bind to localhost.", "CWE-306"),
    3389: ("RDP", Severity.MEDIUM, "Remote Desktop exposed — brute-force/patch target.",
           "Restrict via VPN/NLA; never expose RDP to the internet.", "CWE-284"),
    5900: ("VNC", Severity.HIGH, "VNC often weakly/again un-authenticated.",
           "Tunnel VNC over SSH/VPN; require strong auth.", "CWE-306"),
}


@register
class MisconfigModule(BaseModule):
    id = "vuln.misconfig"
    name = "Misconfiguration Review"
    phase = Phase.VULN_ASSESS
    description = "Flag risky exposed services from the inventory (no probing)."
    inputs = [
        ModuleInput("target", "Host (blank = all)", default="", required=False),
    ]

    def run(self, ctx: ModuleContext, params) -> Iterator[Finding]:
        host = params.get("target", "").strip()
        services = ctx.workspace.services(host or None)
        if not services:
            yield Finding(title="No services in inventory to review",
                          target=host or "project", severity=Severity.INFO,
                          description="Run scanning first.")
            return
        count = 0
        for svc in services:
            port = svc.get("port")
            if port in RISKY_PORTS:
                label, sev, why, fix, cwe = RISKY_PORTS[port]
                count += 1
                yield Finding(
                    title=f"Exposed {label} service on {svc['host']}:{port}",
                    target=svc["host"], severity=sev,
                    description=why,
                    remediation=fix, cwe=[cwe],
                    evidence=f"{label} ({port}/{svc.get('proto','tcp')}) "
                             f"{svc.get('product','')} {svc.get('version','')}".strip(),
                    data={"port": port},
                )
        if count == 0:
            yield Finding(title="No high-risk exposed services identified",
                          target=host or "project", severity=Severity.INFO)
