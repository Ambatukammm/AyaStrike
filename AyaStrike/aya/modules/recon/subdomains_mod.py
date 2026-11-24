"""Passive recon: subdomain discovery.

Two complementary, passive-to-semi-passive techniques:

  * Certificate Transparency (crt.sh): purely passive — queries public CT logs
    for certificates issued to the domain. No contact with the target.
  * DNS wordlist resolution: resolves ``word.domain`` candidates. This only
    sends DNS queries to resolvers, not traffic to the target host, but is
    gated by the rate limiter and respects cancellation.

Discovered subdomains that resolve are recorded as hosts.
"""

from __future__ import annotations

import json
from typing import Iterator

from aya.core import net
from aya.core.config import data_dir
from aya.core.plugins import register
from aya.modules.base import BaseModule, Finding, ModuleContext, ModuleInput, Phase, Severity

DEFAULT_WORDS = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", "smtp",
    "secure", "vpn", "api", "dev", "staging", "test", "portal", "admin", "m",
    "shop", "ftp", "cpanel", "whm", "autodiscover", "app", "gitlab", "git",
    "jenkins", "jira", "confluence", "docs", "status", "cdn", "assets", "img",
]


def _crtsh(domain: str, settings) -> list[str]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        res = net.http_get(url, settings, timeout=20)
        data = json.loads(res.text)
    except Exception:
        return []
    names: set[str] = set()
    for row in data:
        for n in str(row.get("name_value", "")).splitlines():
            n = n.strip().lstrip("*.").lower()
            if n.endswith(domain):
                names.add(n)
    return sorted(names)


@register
class SubdomainModule(BaseModule):
    id = "recon.subdomains"
    name = "Subdomain Discovery"
    phase = Phase.PASSIVE_RECON
    description = "Find subdomains via Certificate Transparency and DNS wordlist."
    inputs = [
        ModuleInput("target", "Root domain", help="e.g. example.com"),
        ModuleInput("use_crtsh", "Use crt.sh (CT logs)", kind="bool", default=True,
                    required=False),
        ModuleInput("use_wordlist", "DNS wordlist brute", kind="bool", default=True,
                    required=False),
        ModuleInput("wordlist", "Custom wordlist file", kind="file", default="",
                    required=False, help="Optional. One name per line."),
    ]

    def run(self, ctx: ModuleContext, params) -> Iterator[Finding]:
        domain = params["target"].strip().rstrip(".").lower()
        found: dict[str, list[str]] = {}

        if params.get("use_crtsh", True):
            ctx.emit("Querying crt.sh Certificate Transparency logs…", "info")
            for name in _crtsh(domain, ctx.settings):
                if ctx.cancel.is_set():
                    break
                ips = net.resolve(name)
                found.setdefault(name, [])
                if ips:
                    found[name] = ips

        if params.get("use_wordlist", True):
            words = list(DEFAULT_WORDS)
            wl = params.get("wordlist", "")
            if wl:
                try:
                    words = [l.strip() for l in open(wl, encoding="utf-8") if l.strip()]
                except OSError:
                    ctx.emit(f"Could not read wordlist {wl}; using default.", "warn")
            ctx.emit(f"Resolving {len(words)} candidate subdomains…", "info")
            for w in words:
                if ctx.cancel.is_set():
                    break
                if not ctx.gate():
                    break
                host = f"{w}.{domain}"
                ips = net.resolve(host)
                if ips:
                    found[host] = ips
                    ctx.emit(f"  found {host} -> {', '.join(ips)}", "success")

        if not found:
            yield Finding(
                title=f"No subdomains discovered for {domain}",
                target=domain, severity=Severity.INFO,
            )
            return

        resolved = {k: v for k, v in found.items() if v}
        for host, ips in resolved.items():
            for ip in ips:
                ctx.workspace.upsert_host(ip, hostname=host)

        evidence = "\n".join(
            f"{h}  ->  {', '.join(ips) if ips else '(no A record)'}"
            for h, ips in sorted(found.items())
        )
        yield Finding(
            title=f"{len(found)} subdomain(s) discovered for {domain}",
            target=domain, severity=Severity.INFO,
            description=f"{len(resolved)} resolve to an IP address.",
            evidence=evidence, data={"subdomains": found},
        )
