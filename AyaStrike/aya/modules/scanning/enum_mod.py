"""Active scanning: SMB / DNS / SNMP enumeration.

Lightweight enumeration that prefers well-known CLI tools when present
(``nmap`` NSE scripts, ``snmpwalk``) and otherwise performs a minimal native
check so the module still returns something useful. All targets are
scope-checked.
"""

from __future__ import annotations

import socket
from typing import Iterator

from aya.core import net, runner
from aya.core.plugins import register
from aya.modules.base import BaseModule, Finding, ModuleContext, ModuleInput, Phase, Severity


@register
class SmbEnumModule(BaseModule):
    id = "scan.smb_enum"
    name = "SMB Enumeration"
    phase = Phase.ACTIVE_SCAN
    description = "Enumerate SMB shares/OS via nmap NSE (smb-* scripts)."
    inputs = [ModuleInput("target", "Host / IP")]

    def run(self, ctx: ModuleContext, params) -> Iterator[Finding]:
        host = params["target"].strip()
        ctx.scope.require(host)
        if not net.tcp_connect(host, 445, ctx.settings.connect_timeout):
            yield Finding(title=f"SMB (445/tcp) not open on {host}", target=host,
                          severity=Severity.INFO)
            return
        cmd = [ctx.settings.nmap_path or "nmap", "-p", "445", "--script",
               "smb-os-discovery,smb-enum-shares,smb-security-mode", host]
        try:
            result = runner.run(cmd, timeout=300,
                                on_line=lambda l: ctx.emit(l, "info"),
                                cancel=ctx.cancel)
            evidence = result.stdout
        except runner.ToolNotFound:
            evidence = "nmap not installed — only confirmed 445/tcp is open."
        sev = Severity.MEDIUM if "signing: disabled" in evidence.lower() else Severity.INFO
        yield Finding(
            title=f"SMB enumeration for {host}", target=host, severity=sev,
            evidence=evidence[:8000],
            remediation="Disable SMBv1, require message signing, restrict null sessions.",
            cwe=["CWE-287"] if sev != Severity.INFO else [],
        )


@register
class SnmpEnumModule(BaseModule):
    id = "scan.snmp_enum"
    name = "SNMP Enumeration"
    phase = Phase.ACTIVE_SCAN
    description = "Check SNMP for default community strings (snmpwalk/nmap)."
    inputs = [
        ModuleInput("target", "Host / IP"),
        ModuleInput("communities", "Community strings", default="public,private",
                    required=False),
    ]

    def run(self, ctx: ModuleContext, params) -> Iterator[Finding]:
        host = params["target"].strip()
        ctx.scope.require(host)
        comms = [c.strip() for c in params.get("communities", "public,private").split(",")]
        cmd = [ctx.settings.nmap_path or "nmap", "-sU", "-p", "161",
               "--script", "snmp-info", host]
        try:
            result = runner.run(cmd, timeout=180,
                                on_line=lambda l: ctx.emit(l, "info"),
                                cancel=ctx.cancel)
            evidence = result.stdout
        except runner.ToolNotFound:
            evidence = (f"nmap not installed. Try: snmpwalk -v2c -c <community> {host}\n"
                        f"Communities to test: {', '.join(comms)}")
        weak = any(c in evidence.lower() for c in ("public", "private"))
        yield Finding(
            title=f"SNMP check for {host}", target=host,
            severity=Severity.HIGH if weak and "open" in evidence.lower() else Severity.INFO,
            evidence=evidence[:8000],
            remediation="Disable SNMP if unused; use SNMPv3 with auth; never leave "
                        "default community strings.",
            cwe=["CWE-1392"] if weak else [],
        )


@register
class DnsEnumModule(BaseModule):
    id = "scan.dns_enum"
    name = "DNS Enumeration (zone transfer)"
    phase = Phase.ACTIVE_SCAN
    description = "Attempt AXFR zone transfer against the domain's name servers."
    inputs = [ModuleInput("target", "Domain")]

    def run(self, ctx: ModuleContext, params) -> Iterator[Finding]:
        domain = params["target"].strip().rstrip(".")
        try:
            import dns.resolver  # type: ignore
            import dns.query  # type: ignore
            import dns.zone  # type: ignore
        except Exception:
            yield Finding(title="dnspython required for zone transfer", target=domain,
                          severity=Severity.INFO,
                          description="pip install dnspython to enable AXFR checks.")
            return
        try:
            ns_records = [r.to_text() for r in dns.resolver.resolve(domain, "NS")]
        except Exception:
            yield Finding(title=f"No NS records for {domain}", target=domain,
                          severity=Severity.INFO)
            return
        vulnerable = []
        for ns in ns_records:
            ns = ns.rstrip(".")
            ctx.scope.require(ns)
            if not ctx.gate():
                break
            try:
                xfr = dns.query.xfr(ns, domain, timeout=ctx.settings.read_timeout)
                zone = dns.zone.from_xfr(xfr)
                names = [n.to_text() for n in zone.nodes.keys()]
                vulnerable.append((ns, names))
                ctx.emit(f"  AXFR allowed by {ns} ({len(names)} records!)", "error")
            except Exception:
                ctx.emit(f"  {ns}: zone transfer refused (good)", "success")
        if vulnerable:
            ev = "\n\n".join(f"{ns}:\n  " + "\n  ".join(n) for ns, n in vulnerable)
            yield Finding(
                title=f"Zone transfer (AXFR) allowed on {domain}",
                target=domain, severity=Severity.HIGH,
                description="A name server exposed the full zone via AXFR.",
                evidence=ev[:8000],
                remediation="Restrict AXFR to authorised secondary name servers only.",
                cwe=["CWE-200"],
            )
        else:
            yield Finding(title=f"Zone transfer refused for {domain}",
                          target=domain, severity=Severity.INFO)
