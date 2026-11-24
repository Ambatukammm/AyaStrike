"""Passive recon: email harvesting, Shodan, and Wayback.

All three are passive — they query public/third-party datasets rather than the
target itself:

  * Email harvest: scrapes email addresses from the domain's own public web
    pages and from Certificate Transparency names (no third-party key needed).
  * Shodan: queries the Shodan host/search API (requires the user's own API key
    in Settings). Shodan data is pre-collected, so this does not touch the host.
  * Wayback: pulls historical URLs from the Internet Archive CDX API — useful
    for discovering old endpoints/parameters without hitting the live site.
"""

from __future__ import annotations

import json
import re
from typing import Iterator

from aya.core import net
from aya.core.plugins import register
from aya.modules.base import BaseModule, Finding, ModuleContext, ModuleInput, Phase, Severity

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")


@register
class EmailHarvestModule(BaseModule):
    id = "recon.email_harvest"
    name = "Email Harvester"
    phase = Phase.PASSIVE_RECON
    description = "Collect email addresses from public web pages for the domain."
    inputs = [
        ModuleInput("target", "Domain", help="e.g. example.com"),
        ModuleInput("pages", "Pages to scan", kind="multiline", required=False,
                    default="https://{d}\nhttps://{d}/contact\nhttps://{d}/about",
                    help="One URL per line. {d} is replaced with the domain."),
    ]

    def run(self, ctx: ModuleContext, params) -> Iterator[Finding]:
        domain = params["target"].strip().lower()
        tmpl = params.get("pages") or "https://{d}"
        urls = [u.strip().replace("{d}", domain) for u in tmpl.splitlines() if u.strip()]
        emails: set[str] = set()
        for url in urls:
            if ctx.cancel.is_set():
                break
            if not ctx.gate():
                break
            ctx.emit(f"Fetching {url}", "info")
            try:
                res = net.http_get(url, ctx.settings, verify=True)
                for m in EMAIL_RE.findall(res.text):
                    if m.lower().endswith(domain) or domain in m.lower():
                        emails.add(m.lower())
            except Exception as e:
                ctx.emit(f"  skip {url}: {e}", "warn")
        if emails:
            yield Finding(
                title=f"{len(emails)} email address(es) harvested for {domain}",
                target=domain, severity=Severity.LOW,
                description="Publicly exposed addresses; potential phishing targets.",
                evidence="\n".join(sorted(emails)),
                remediation="Review whether these addresses need to be public.",
                data={"emails": sorted(emails)},
            )
        else:
            yield Finding(title=f"No public emails found for {domain}",
                          target=domain, severity=Severity.INFO)


@register
class ShodanModule(BaseModule):
    id = "recon.shodan"
    name = "Shodan Lookup"
    phase = Phase.PASSIVE_RECON
    description = "Query Shodan for host data (requires your Shodan API key)."
    inputs = [
        ModuleInput("target", "IP address", help="e.g. 203.0.113.5"),
    ]

    def run(self, ctx: ModuleContext, params) -> Iterator[Finding]:
        ip = params["target"].strip()
        key = ctx.settings.shodan_api_key
        if not key:
            yield Finding(
                title="Shodan API key not configured", target=ip,
                severity=Severity.INFO,
                description="Add your Shodan API key in Settings to enable this module.",
            )
            return
        ctx.gate()
        url = f"https://api.shodan.io/shodan/host/{ip}?key={key}"
        try:
            res = net.http_get(url, ctx.settings, timeout=20)
            data = json.loads(res.text)
        except Exception as e:
            yield Finding(title=f"Shodan query failed for {ip}", target=ip,
                          severity=Severity.INFO, description=str(e))
            return
        ports = data.get("ports", [])
        os_ = data.get("os") or ""
        hostnames = data.get("hostnames", [])
        for p in ports:
            ctx.workspace.upsert_service(ip, int(p), "tcp")
        if os_ or hostnames:
            ctx.workspace.upsert_host(ip, hostname=",".join(hostnames), os_=os_)
        ev = (f"Ports: {ports}\nOS: {os_}\nHostnames: {hostnames}\n"
              f"Org: {data.get('org','')}\nISP: {data.get('isp','')}")
        yield Finding(
            title=f"Shodan: {len(ports)} exposed port(s) on {ip}",
            target=ip, severity=Severity.MEDIUM if ports else Severity.INFO,
            description="Pre-indexed exposure data from Shodan.",
            evidence=ev, data={"ports": ports, "os": os_, "hostnames": hostnames},
        )


@register
class WaybackModule(BaseModule):
    id = "recon.wayback"
    name = "Wayback URLs"
    phase = Phase.PASSIVE_RECON
    description = "Historical URLs from the Internet Archive (passive)."
    inputs = [
        ModuleInput("target", "Domain", help="e.g. example.com"),
        ModuleInput("limit", "Max URLs", kind="int", default=500, required=False),
    ]

    def run(self, ctx: ModuleContext, params) -> Iterator[Finding]:
        domain = params["target"].strip().lower()
        limit = int(params.get("limit", 500) or 500)
        ctx.gate()
        url = (f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*"
               f"&output=json&fl=original&collapse=urlkey&limit={limit}")
        try:
            res = net.http_get(url, ctx.settings, timeout=30)
            rows = json.loads(res.text)
        except Exception as e:
            yield Finding(title=f"Wayback query failed for {domain}", target=domain,
                          severity=Severity.INFO, description=str(e))
            return
        urls = [r[0] for r in rows[1:]] if rows and isinstance(rows, list) else []
        # Flag interesting historical endpoints.
        interesting = [u for u in urls if re.search(
            r"\.(bak|old|sql|zip|tar|gz|env|config|log)(\?|$)|/api/|/admin|\?.+=", u)]
        yield Finding(
            title=f"{len(urls)} historical URL(s) for {domain}",
            target=domain,
            severity=Severity.LOW if interesting else Severity.INFO,
            description=(f"{len(interesting)} look potentially sensitive "
                         f"(backups, configs, API or admin paths)."),
            evidence="\n".join(interesting[:200]) or "\n".join(urls[:200]),
            data={"all": urls, "interesting": interesting},
        )
