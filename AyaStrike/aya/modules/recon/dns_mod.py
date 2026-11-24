"""Passive recon: DNS records.

Enumerates common DNS record types. Uses ``dnspython`` if installed for full
record-type support; otherwise falls back to stdlib resolution for A/AAAA so
the module still returns useful data on a clean Python install.
"""

from __future__ import annotations

from typing import Iterator

from aya.core import net
from aya.core.plugins import register
from aya.modules.base import BaseModule, Finding, ModuleContext, ModuleInput, Phase, Severity

try:
    import dns.resolver  # type: ignore
    _HAS_DNSPYTHON = True
except Exception:
    _HAS_DNSPYTHON = False

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV", "CAA"]


@register
class DnsModule(BaseModule):
    id = "recon.dns"
    name = "DNS Records"
    phase = Phase.PASSIVE_RECON
    description = "Enumerate A/AAAA/MX/NS/TXT/SOA/CNAME/SRV/CAA records."
    inputs = [
        ModuleInput("target", "Domain", help="e.g. example.com"),
    ]

    def run(self, ctx: ModuleContext, params) -> Iterator[Finding]:
        domain = params["target"].strip().rstrip(".")
        results: dict[str, list[str]] = {}

        if _HAS_DNSPYTHON:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = ctx.settings.read_timeout
            for rtype in RECORD_TYPES:
                ctx.gate()
                if ctx.cancel.is_set():
                    return
                try:
                    answers = resolver.resolve(domain, rtype)
                    results[rtype] = [a.to_text() for a in answers]
                    ctx.emit(f"DNS {rtype}: {len(results[rtype])} record(s)", "success")
                except Exception:
                    continue
        else:
            ctx.emit("dnspython not installed — resolving A/AAAA via stdlib only.", "warn")
            ips = net.resolve(domain)
            if ips:
                results["A/AAAA"] = ips

        if not results:
            yield Finding(
                title=f"No DNS records resolved for {domain}",
                target=domain, severity=Severity.INFO,
                description="No records returned. Domain may not exist or DNS is filtered.",
            )
            return

        evidence = "\n".join(f"{k}:\n  " + "\n  ".join(v) for k, v in results.items())

        # Surface security-relevant TXT findings (SPF/DMARC) as their own notes.
        txt = " ".join(results.get("TXT", []))
        if "v=spf1" not in txt:
            yield Finding(
                title="No SPF record found", target=domain, severity=Severity.LOW,
                description="No SPF (v=spf1) TXT record detected for the domain.",
                remediation="Publish an SPF record to reduce email spoofing risk.",
                cwe=["CWE-358"],
            )

        yield Finding(
            title=f"DNS records for {domain}", target=domain, severity=Severity.INFO,
            description=f"Enumerated {len(results)} record type(s).",
            evidence=evidence, data=results,
        )

        # Record resolved addresses into host inventory.
        for ip in results.get("A", []) + results.get("AAAA", []) + results.get("A/AAAA", []):
            ctx.workspace.upsert_host(ip, hostname=domain)
